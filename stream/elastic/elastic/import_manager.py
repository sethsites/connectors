import re
import urllib.parse
from datetime import datetime, timezone
from logging import getLogger

from datemath import dm
from elasticsearch import Elasticsearch, NotFoundError, RequestError
from pycti import OpenCTIConnectorHelper
from scalpl import Cut

from . import DM_DEFAULT_FMT, LOGGER_NAME, RE_DATEMATH
from .utils import remove_nones

logger = getLogger(LOGGER_NAME)

entity_field_mapping = {
    "id": "threatintel.opencti.internal_id",
    "valid_from": "threatintel.opencti.valid_from",
    "valid_until": "threatintel.opencti.valid_until",
    "x_opencti_detection": "threatintel.opencti.enable_detection",
    "pattern": "threatintel.opencti.original_pattern",
    "pattern_type": "threatintel.opencti.pattern_type",
    "created_at": "threatintel.opencti.created_at",
    "updated_at": "threatintel.opencti.updated_at",
    "x_opencti_score": ["risk_score", "risk_score_norm"],
    "confidence": ["threatintel.confidence", "threatintel.confidence_norm"],
    "x_mitre_platforms": "threatintel.opencti.mitre.platforms",
    "standard_id": "threatintel.stix.id",
    "revoked": "threatintel.opencti.revoked",
    "description": "threatintel.indicator.description",
}


class StixManager(object):
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        elasticsearch_client: Elasticsearch,
        config: dict[str, str],
        datadir: str,
    ):
        self.helper: OpenCTIConnectorHelper = helper
        self.es_client: Elasticsearch = elasticsearch_client
        self.config: Cut = Cut(config)
        self.datadir: str = datadir
        self.idx: str = self.config.get("output.elasticsearch.index")
        self.idx_pattern: str = self.config.get("setup.template.pattern")
        self.pattern: re.Pattern = re.compile(RE_DATEMATH)

        self._setup_elasticsearch_index()

    def _setup_elasticsearch_index(self) -> None:
        # Index pattern not yet implemented
        pass

    def import_cti_event(
        self, timestamp: datetime, data: dict, is_update: bool = False
    ) -> dict:

        try:
            # Submit to Elastic index

            _document = data
            _document["@timestamp"] = timestamp
            _write_idx = self.idx
            # Render date-specific index if we're using logstash style indices
            m = self.pattern.search(_write_idx)
            if m is not None:
                m = m.groupdict()
                if m.get("modulo", None) is not None:
                    _fmt = m.get("format") or DM_DEFAULT_FMT
                    logger.debug(f"{m['modulo']} -> {_fmt}")
                    _val = dm(m.get("modulo"), now=timestamp).format(_fmt)
                    _write_idx = self.pattern.sub(_val, _write_idx)

            # Submit to Elastic index
            logger.debug(f"Indexing doc to {_write_idx}:\n {_document}")
            self.es_client.index(
                index=_write_idx,
                id=data["x_opencti_id"],
                body=_document,
            )

        except RequestError as err:
            logger.error("Unexpected error:", err, data)
        except Exception as err:
            logger.error("Something else happened", err, data)

        return data

    def delete_cti_event(self, data: dict) -> None:
        _result: dict = {}
        try:
            _result = self.es_client.delete(
                index=self.idx_pattern, id=data["x_opencti_id"], doc_type="_doc"
            )
        except NotFoundError:
            logger.warn(f"Document id {data['x_opencti_id']} not found in index")

        if _result.get("result", None) == "deleted":
            logger.debug(f"Document id {data['x_opencti_id']} deleted")

        return


class IntelManager(object):
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        elasticsearch_client: Elasticsearch,
        config: dict[str, str],
        datadir: str,
    ):
        self.helper: OpenCTIConnectorHelper = helper
        self.es_client: Elasticsearch = elasticsearch_client
        self.config: Cut = Cut(config)
        self.datadir: str = datadir

        self.idx: str = self.config.get("output.elasticsearch.index")
        self.idx_pattern: str = self.config.get("setup.template.pattern")
        self.write_idx: str = self.config.get("output.elasticsearch.index")

        if self.config.get("setup.ilm.enabled", False) is True:
            self.write_idx = self.config.get("setup.ilm.rollover_alias", "opencti")

        self.pattern = re.compile(RE_DATEMATH)

        self._setup_elasticsearch_index()

    def _setup_elasticsearch_index(self) -> None:
        import os
        from string import Template

        logger.info("Setting up Elasticsearch for OpenCTI Connector")
        assert self.es_client.ping()

        _ilm_enabled: bool = self.config.get("setup.ilm.enabled", True)
        _policy_name: str = self.config.get("setup.ilm.policy_name", "opencti")
        _policy: str = None

        try:
            _policy: str = self.es_client.ilm.get_lifecycle(policy=_policy_name)
        except NotFoundError as err:
            logger.warning(f"HTTP {err.status_code}: {err.info['error']['reason']}")

        if _ilm_enabled is True:
            # Create ILM policy if needed
            if (_policy is None) or (
                self.config.get("setup.ilm.overwrite", None) is True
            ):
                logger.info(f"Creating ILM policy {_policy_name}")
                with open(
                    os.path.join(self.datadir, "ecs-indicator-index-ilm.json")
                ) as f:
                    content = f.read()
                    self.es_client.ilm.put_lifecycle(policy=_policy_name, body=content)

        values = {
            "policy_name": _policy_name,
            "rollover_alias": self.config.get("setup.ilm.rollover_alias", "opencti"),
            "pattern": self.idx_pattern,
        }

        # Create index template
        if self.config.get("setup.template.enabled", True) is True:
            _template_name: str = self.config.get("setup.template.name", "opencti")

            with open(
                os.path.join(self.datadir, "ecs-indicator-index-template.json")
            ) as f:
                tpl = Template(f.read())
                content = tpl.substitute(values)

            logger.info(f"Installing index template: {_template_name}")
            self.es_client.indices.put_index_template(_template_name, body=content)

        # Create initial index, if needed
        logger.debug(f"Checking if index pattern exists: {self.idx_pattern}")
        if (
            len(
                self.es_client.indices.resolve_index(name=self.idx_pattern).get(
                    "indices", []
                )
            )
            < 1
        ):
            logger.debug("No indices matching pattern exist.")

            if _ilm_enabled is True:
                # Create ILM alias and initialize index
                _alias = self.config.get("setup.ilm.rollover_alias", "opencti")
                _ilm_pattern = self.config.get("setup.ilm.pattern", "{now/d}-000001")
                _initial_idx = f"{_alias}-{_ilm_pattern}"
            else:
                _initial_idx = self.config.get(
                    "output.elasticsearch.index", "opencti-{now/d}"
                )

            logger.info(f"Parsing index pattern: {_initial_idx}")
            m = self.pattern.search(_initial_idx)
            if m is not None:
                _initial_idx = f"<{_initial_idx}>"
                m = m.groupdict()

            # logger.debug(f"Matches: {m}")
            # if m.get("modulo", None) is not None:
            #     _fmt = m.get("format") or DM_DEFAULT_FMT
            #     logger.debug(f"{m['modulo']} -> {_fmt}")
            #     _val = dm(m.get("modulo")).format(_fmt)
            #     logger.debug(f"Timestamp string from arrow {_val}")
            #     _initial_idx = self.pattern.sub(_val, _initial_idx)

            logger.info(f"Initial index: {_initial_idx}\nAlias: {_alias}")

            if _ilm_enabled is True and (
                not self.es_client.indices.exists_alias(
                    index=self.idx_pattern, name=_alias
                )
            ):
                logger.info(f"Creating alias '{_alias}' to pattern '{_initial_idx}'")
                _settings: str = f"""
                {{
                    "aliases": {{
                        "{_alias}": {{ "is_write_index": true }}
                    }}
                }}
                """

                self.write_idx = _alias
            else:
                logger.info(f"Alias {_alias} already exists or not being used")
                _settings = "{}"

            self.es_client.index(index=_initial_idx, body=_settings)
            logger.info(f"Initial index {_initial_idx} created.")

        else:
            logger.info("Index already exists")

    def import_cti_event(
        self, timestamp: datetime, data: dict, is_update: bool = False
    ) -> dict:
        logger.debug(f"Querying indicator: { data['x_opencti_id']}")
        entity = self.helper.api.indicator.read(id=data["x_opencti_id"])

        logger.debug(entity)

        _result: dict = {}
        _document: Cut = {}

        if data["type"] != "indicator":
            logger.error(
                f"Data type unsupported: {data['type']}. Only 'indicators are currently supported."
            )
            return None

        if is_update is True:
            update_time: str = (
                datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
            )
            try:
                # Attempt to retreive existing document
                logger.debug(f"Retrieving document id: {data['x_opencti_id']}")
                _result = self.es_client.get(
                    index=self.idx_pattern, id=data["x_opencti_id"], doc_type="_doc"
                )

            except NotFoundError:
                logger.warn(
                    f"Document not found to update at /{self.idx}/_doc/{data['x_opencti_id']}"
                )
                logger.warn("Skipping")
                return {}

            except RequestError as err:
                logger.error(
                    f"Unexpected error retreiving document at /{self.idx}/_doc/{data['x_opencti_id']}:",
                    err.__dict__,
                )

            if _result["found"] is True:
                _document = Cut(_result["_source"])
                _write_idx = _result["_index"]

            if data.get("x_data_update", None):
                if data["x_data_update"].get("replace", None):
                    if entity["pattern_type"] == "stix":
                        # Pull in any indicator updates
                        _indicator: dict = self._create_ecs_indicator_stix(entity)
                        if _indicator == {}:
                            return {}
                        _document["threatintel.indicator"] = _indicator
                        if entity.get("killChainPhases", None):
                            phases = []
                            for phase in sorted(
                                entity["killChainPhases"],
                                key=lambda i: (
                                    i["kill_chain_name"],
                                    i["x_opencti_order"],
                                ),
                            ):
                                phases.append(
                                    {
                                        "killchain_name": phase["kill_chain_name"],
                                        "phase_name": phase["phase_name"],
                                        "opencti_phase_order": phase["x_opencti_order"],
                                    }
                                )

                            _document.setdefault(
                                "threatintel.opencti.killchain_phases", phases
                            )
                    else:
                        logger.warning(
                            f"Unsupported indicator pattern type: {entity['pattern_type']}. Skipping."
                        )
                        return _document

                    for k, v in data["x_data_update"].get("replace", {}).items():
                        logger.debug(
                            f"Updating field {k} -> {entity_field_mapping.get(k)} to {v}"
                        )
                        try:
                            _field = entity_field_mapping.get(k)
                            _document.setdefault(_field, v)
                            _document[_field] = v
                        except KeyError as err:
                            logger.error(f"Unable to find field mapping for {k}", err)

                    _document["threatintel.opencti.updated_at"] = update_time

                    #  This scrubs the Cut object and returns a dict
                    _document = remove_nones(_document)

                    try:
                        # Don't render timestamped index since this is an update
                        # Submit to Elastic index
                        logger.debug(f"Updating doc to {_write_idx}:\n {_document}")
                        self.es_client.index(
                            index=_write_idx,
                            id=data["x_opencti_id"],
                            body=_document,
                        )
                    except RequestError as err:
                        logger.error("Unexpected error:", err, _document)
                    except Exception as err:
                        logger.error("Something else happened", err, _document)

                    return _document

        creation_time: str = (
            datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
        )

        _document: dict = {
            "@timestamp": timestamp,
            "event": {
                "created": creation_time,
                "kind": "enrichment",
                "category": "threat",
                "type": "indicator",
                "dataset": "threatintel.opencti",
            },
            "threatintel": {},
        }

        if len(entity.get("externalReferences", [])) > 0:
            _document["event"]["reference"] = [
                item.get("url", None) for item in entity["externalReferences"]
            ]

        if self.config.get("opencti.platform_url") is not None:
            _document["event"]["url"] = urllib.parse.urljoin(
                f"{self.config.get('opencti.platform_url')}",
                f"/dashboard/observations/indicators/{entity['id']}",
            )

        _document["event"]["risk_score"] = entity.get("x_opencti_score", None)
        _document["event"]["risk_score_norm"] = entity.get("x_opencti_score", None)
        _document["threatintel"]["confidence"] = entity.get("confidence", None)
        _document["threatintel"]["confidence_norm"] = entity.get("confidence", None)

        _document["threatintel"]["opencti"] = {
            "internal_id": entity.get("id", None),
            "valid_from": entity.get("valid_from", None),
            "valid_until": entity.get("valid_until", None),
            "enable_detection": entity.get("x_opencti_detection", None),
            "original_pattern": entity.get("pattern", None),
            "pattern_type": entity.get("pattern_type", None),
            "created_at": entity.get("created_at", None),
            "updated_at": entity.get("created_at", None),
            "revoked": entity.get("revoked", None),
        }

        if entity.get("killChainPhases", None):
            phases = []
            for phase in sorted(
                entity["killChainPhases"],
                key=lambda i: (i["kill_chain_name"], i["x_opencti_order"]),
            ):
                phases.append(
                    {
                        "killchain_name": phase["kill_chain_name"],
                        "phase_name": phase["phase_name"],
                        "opencti_phase_order": phase["x_opencti_order"],
                    }
                )

            _document["threatintel"]["opencti"]["killchain_phases"] = phases

        if entity.get("x_mitre_platforms", None):
            _document["threatintel"]["opencti"]["mitre"] = {
                "platforms": entity.get("x_mitre_platforms", None)
            }

        if entity["pattern_type"] == "stix":
            _indicator: dict = self._create_ecs_indicator_stix(entity)
            if _indicator == {}:
                return {}

            _document["threatintel"]["stix"] = {"id": entity.get("standard_id")}
            _document["threatintel"]["indicator"] = _indicator

        else:
            logger.warning(
                f"Unsupported indicator pattern type: {entity['pattern_type']}. Skipping."
            )
            return {}

        _document = remove_nones(_document)

        try:
            # Render date-specific index, if we're doing logstash style indices
            _write_idx = self.write_idx
            m = self.pattern.search(_write_idx)
            if m is not None:
                m = m.groupdict()
                if m.get("modulo", None) is not None:
                    _fmt = m.get("format") or DM_DEFAULT_FMT
                    logger.debug(f"{m['modulo']} -> {_fmt}")
                    _val = dm(m.get("modulo"), now=timestamp).format(_fmt)
                    _write_idx = self.pattern.sub(_val, _write_idx)

            # Submit to Elastic index
            logger.debug(f"Indexing doc to {_write_idx}:\n {_document}")
            self.es_client.index(
                index=_write_idx,
                id=data["x_opencti_id"],
                body=_document,
            )
        except RequestError as err:
            logger.error("Unexpected error:", err, _document)
        except Exception as err:
            logger.error("Something else happened", err, _document)

        return _document

    def delete_cti_event(self, data: dict) -> None:

        logger.debug(f"Deleting {data}")
        _result: dict = {}

        if data["type"] != "indicator":
            logger.error(
                f"Data type unsupported: {data['type']}. Only 'indicator' types are currently supported."
            )
            return None

        try:
            _result = self.es_client.delete(
                index=self.idx_pattern, id=data["x_opencti_id"], doc_type="_doc"
            )
        except NotFoundError:
            logger.warn(f"Document id {data['x_opencti_id']} not found in index")

        if _result.get("result", None) == "deleted":
            logger.debug(f"Document id {data['x_opencti_id']} deleted")

        return

    def _create_ecs_indicator_stix(self, entity: dict):
        from .stix2ecs import StixIndicator

        try:
            item = StixIndicator.parse_pattern(entity["pattern"])[0]
        except NotImplementedError as e:
            logger.warning(e)
            return {}

        _indicator = item.get_ecs_indicator()

        if entity.get("objectMarking", None):
            markings = {}
            for mark in entity["objectMarking"]:
                markings[mark["definition_type"].lower()] = []

            for mark in entity["objectMarking"]:
                if len(mark["definition"].split(":")) > 1:
                    value = ":".join(mark["definition"].split(":")[1:]).lower()
                else:
                    value = mark["definition"].lower()

                markings[mark["definition_type"].lower()].append(value)

            _indicator["marking"] = markings

        if entity.get("description", None):
            _indicator["description"] = entity["description"]

        if entity.get("createdBy", None):
            _indicator["provider"] = entity["createdBy"]["name"]

        return _indicator
