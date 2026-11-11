"""
Investigates suspicious source IP addresses associated with RDP brute-force attempts. Enriches IP addresses using AbuseIPDB and VirusTotal, evaluates threat intelligence scores, and flags potentially malicious activity for further SOC investigation.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'lookup_ip_1' block
    lookup_ip_1(container=container)

    return

@phantom.playbook_block()
def lookup_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("lookup_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'lookup_ip_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "days": 10,
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("lookup ip", parameters=parameters, name="lookup_ip_1", assets=["abuseipdb_soc_lab"], callback=ip_reputation_1)

    return


@phantom.playbook_block()
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation_1", assets=["virustotal_soc_lab"], callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["lookup_ip_1:action_result.data.*.data.abuseConfidenceScore", ">=", 75],
            ["ip_reputation_1:action_result.data.*.attributes.last_analysis_stats.malicious", ">=", 5]
        ],
        conditions_dps=[
            ["lookup_ip_1:action_result.data.*.data.abuseConfidenceScore", ">=", 75],
            ["ip_reputation_1:action_result.data.*.attributes.last_analysis_stats.malicious", ">=", 5]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        container_update_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    container_update_2(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def container_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("container_update_1() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "name": None,
        "tags": "rdp_bruteforce, threat_intel_high_risk",
        "label": None,
        "owner": None,
        "status": "open",
        "severity": "high",
        "input_json": None,
        "description": None,
        "sensitivity": None,
        "container_input": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_update", parameters=parameters, name="container_update_1")

    return


@phantom.playbook_block()
def container_update_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("container_update_2() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "name": None,
        "tags": "rdp_bruteforce, threat_intel_low_risk",
        "label": None,
        "owner": None,
        "status": "open",
        "severity": "medium",
        "input_json": None,
        "description": None,
        "sensitivity": None,
        "container_input": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_update", parameters=parameters, name="container_update_2")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return