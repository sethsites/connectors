import json
import re
import traceback
from datetime import datetime
from threading import Event, Thread

from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper
from scalpl import Cut
from stix_shifter.stix_translation import stix_translation
from stix_shifter.stix_transmission import stix_transmission

from managers import EnvironmentManager, IncidentManager, RelationshipManager
from scanners import Scanner


class IndicatorIngest(Scanner):
    def __init__(self,
                 config: Cut,
                 env_manager: EnvironmentManager,
                 es: Elasticsearch,
                 helper: OpenCTIConnectorHelper,
                 incident_manager: IncidentManager,
                 relationship_manager: RelationshipManager,
                 shutdown_event: Event):
        super(IndicatorIngest, self).__init__(config, env_manager, es, helper, incident_manager,
                                              relationship_manager, shutdown_event)
        self.state_tracking_token = "indicator_ingest_scanner_last_run"

    def run(self) -> None:
        self.helper.log_info("Indicator ingest thread starting")

        """Main loop"""
        while not self.shutdown_event.is_set():
            try:
                run_stuff = self.get_should_run(self.state_tracking_token)
                if "should_run" in run_stuff and run_stuff["should_run"]:
                    now = datetime.utcfromtimestamp(run_stuff["timestamp"])
                    last_timestamp = datetime.utcfromtimestamp(run_stuff["last_run"]) if run_stuff["last_run"] is not \
                                                                                         None else None
                    regex = re.compile(r"@timestamp:\[[^]]*]")
                    now_timestring = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    if last_timestamp is None:
                        then_timestring = last_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    else:
                        then_timestring = "*"
                    new_timestamp = f"@timestamp:[\"{then_timestring}\" TO \"{now_timestring}\"]"
                    translation = stix_translation.StixTranslation()

                    indicator = self.helper.api.indicator.read(id="a3b24470-d6ca-4ad4-bf9e-b1b1ca606911")
                    # self.helper.log_info(f"{indicator}")
                    query_expression = translation.translate('elastic_ecs', 'query', '{}', indicator["pattern"], {})
                    #query_json = json.loads(query_expression)

                    self.helper.log_info(f"{query_expression}")
                    new_query = regex.sub(new_timestamp, query_expression["queries"][0])
                    new_query = new_query.replace(" AND ", " & ").replace(" OR ", " | ")
                    data = {
                        "query_string": {
                            "query": new_query
                        }
                    }
                    self.helper.log_info(f"{json.dumps(data)}")

                    # self.helper.log_info(response)
                    # for indicator in inidicators:
                    #     self.helper.log_info(f"Indicator {indicator}")
                    #     if "pattern" in indicator and indicator["pattern"] != "":
                    #         response = translation.translate('elastic-ecs', 'query', '{}', indicator["pattern"], {})
                    #
                    #         self.helper.log_info(response)
                    #     else:
                    #         self.helper.log_info("Indicator has no pattern or pattern is missing")

                    self.mark_last_run(self.state_tracking_token, run_stuff["timestamp"])
                self.shutdown_event.wait(self.interval)
            except Exception as e:
                self.helper.log_error(f"Exception in indicator scanner {e}")
                traceback.print_exc()
                self.shutdown_event.wait(self.interval)
