#!/usr/bin/env python3
"""Inject CTF flags into CVE lab vulnerable endpoints.

Simple, reliable approach:
1. Find the exploit function in each lab
2. Find the FIRST return statement in that function
3. Inject the flag into the response (in JSON "exploit_flag" field or text line)

Flag format: FLAG{CVE-YYYY-NNNNN_pwned}
Only appears when the correct exploit endpoint is hit.
"""

import os
import re
import json
import sys

LABS_DIR = "/root/NCKH/CloudPentest/cloud_cve_labs"

# Map from auto-detection output
CVE_EXPLOIT_MAP = {
    "CVE-2018-12907": {"file": "fake_crux_cve.py", "func": "config"},
    "CVE-2019-10379": {"file": "fake_jenkins_git_cve.py", "func": "cred_config"},
    "CVE-2021-3062": {"file": "fake_panos_cve.py", "func": "api"},
    "CVE-2021-40829": {"file": "fake_aws_iot_cve.py", "func": "creds"},
    "CVE-2022-1805": {"file": "fake_pcoip_cve.py", "func": "connectors"},
    "CVE-2022-27198": {"file": "fake_jenkins_csrf_cve.py", "func": "credentials"},
    "CVE-2022-27199": {"file": "fake_jenkins_cred_view_cve.py", "func": "system_creds"},
    "CVE-2022-29052": {"file": "fake_jenkins_pipeline_log_cve.py", "func": "creds"},
    "CVE-2022-30570": {"file": "fake_synapse_cve.py", "func": "private_endpoints"},
    "CVE-2022-36917": {"file": "fake_jenkins_crumb_cve.py", "func": "creds"},
    "CVE-2022-46831": {"file": "fake_jenkins_pipeline_cve.py", "func": "creds"},
    "CVE-2023-23408": {"file": "fake_azureml_cve.py", "func": "get_datastore_secrets"},
    "CVE-2023-25956": {"file": "fake_azureml_tokens_cve.py", "func": "list_keys"},
    "CVE-2023-29332": {"file": "fake_azure_aks_cve.py", "func": "secrets"},
    "CVE-2023-32988": {"file": "fake_jenkins_workflow_cve.py", "func": "workspace"},
    "CVE-2023-32989": {"file": "fake_jenkins_groovy_cve.py", "func": "credentials_list"},
    "CVE-2023-33185": {"file": "fake_django_ninja_cve.py", "func": "users"},
    "CVE-2023-35165": {"file": "fake_aws_amplify_cve.py", "func": "get_app"},
    "CVE-2023-41944": {"file": "fake_jenkins_xss_cve.py", "func": "creds"},
    "CVE-2023-43784": {"file": "fake_tfe_cve.py", "func": "workspace_vars"},
    "CVE-2023-50928": {"file": "fake_sap_cloud_cve.py", "func": "admin_config"},
    "CVE-2023-51386": {"file": "fake_aws_codebuild_cve.py", "func": "credentials"},
    "CVE-2024-12408": {"file": "fake_wp_cve.py", "func": "wp_config_backup"},
    "CVE-2024-23680": {"file": "fake_aws_amplify_auth_cve.py", "func": "aws_creds"},
    "CVE-2024-24753": {"file": "fake_bref_lambda_cve.py", "func": "info"},
    "CVE-2024-25131": {"file": "fake_openshift_cve.py", "func": "secrets"},
    "CVE-2024-30164": {"file": "fake_aws_codecommit_cve.py", "func": "vpn_config"},
    "CVE-2024-30165": {"file": "fake_azdevops_spoof3_cve.py", "func": "work_item"},
    "CVE-2024-35261": {"file": "fake_azure_iot_cve.py", "func": "devices"},
    "CVE-2024-35266": {"file": "fake_azure_devops_api_cve.py", "func": "pats"},
    "CVE-2024-35267": {"file": "fake_azdevops_spoof2_cve.py", "func": "pipelines"},
    "CVE-2024-37293": {"file": "fake_aws_cdk_cve.py", "func": "stack_params"},
    "CVE-2024-37325": {"file": "fake_dsvm_cve.py", "func": "credentials"},
    "CVE-2024-38092": {"file": "fake_cyclecloud_cve.py", "func": "clusters"},
    "CVE-2024-38097": {"file": "fake_azure_monitor_cve.py", "func": "workspace_keys"},
    "CVE-2024-38098": {"file": "fake_arc_agent2_cve.py", "func": "extension_logs"},
    "CVE-2024-38157": {"file": "fake_iot_dps_cve.py", "func": "provision_device"},
    "CVE-2024-38158": {"file": "fake_iot_sdk_cve.py", "func": "device_twin"},
    "CVE-2024-38162": {"file": "fake_arc_agent_cve.py", "func": "machine_extensions"},
    "CVE-2024-38179": {"file": "fake_hci_cve.py", "func": "cluster_credentials"},
    "CVE-2024-38188": {"file": "fake_azure_network_cve.py", "func": "env"},
    "CVE-2024-38194": {"file": "fake_azure_functions_cve.py", "func": "function_keys"},
    "CVE-2024-38195": {"file": "fake_cyclecloud_rce_cve.py", "func": "credentials"},
    "CVE-2024-42006": {"file": "fake_aks_arc_cve.py", "func": "certificate_store"},
    "CVE-2025-0508": {"file": "fake_grafana_ssrf_cve.py", "func": "pipeline_cache"},
    "CVE-2025-14503": {"file": "fake_apim_cve.py", "func": "assume_role"},
    "CVE-2025-26683": {"file": "fake_playwright_testing_cve.py", "func": "artifacts"},
    "CVE-2025-27489": {"file": "fake_azure_sql_cve.py", "func": "instance_keys"},
    "CVE-2025-29813": {"file": "fake_azure_devops_cve.py", "func": "variable_groups"},
    "CVE-2025-29827": {"file": "fake_azure_rbac_cve.py", "func": "runbooks"},
    "CVE-2025-29972": {"file": "fake_azure_ssrf_cve.py", "func": "storage_keys"},
    "CVE-2025-29973": {"file": "fake_azure_storage_lib_cve.py", "func": "blob_access"},
    "CVE-2025-30387": {"file": "fake_azure_keyvault_cve.py", "func": "list_secrets"},
    "CVE-2025-30389": {"file": "fake_azure_ai_cve.py", "func": "account_keys"},
    "CVE-2025-30390": {"file": "fake_azureml_eop_cve.py", "func": "compute_keys"},
    "CVE-2025-30392": {"file": "fake_ai_foundry_eop_cve.py", "func": "workspace_connections"},
    "CVE-2025-33072": {"file": "fake_ai_foundry_cve.py", "func": "project_connections"},
    "CVE-2025-33074": {"file": "fake_ai_registry_cve.py", "func": "list_environments"},
    "CVE-2025-47158": {"file": "fake_cosmosdb_cve.py", "func": "list_keys"},
    "CVE-2025-47988": {"file": "fake_azdevops_eop_cve.py", "func": "list_pats"},
    "CVE-2025-47989": {"file": "fake_azdevops_pipeline_cve.py", "func": "build_logs"},
    "CVE-2025-49692": {"file": "fake_frontdoor_cve.py", "func": "get_extension_settings"},
    "CVE-2025-49707": {"file": "fake_appservice_cve.py", "func": "host_keys"},
    "CVE-2025-49746": {"file": "fake_servicebus_cve.py", "func": "list_experiments"},
    "CVE-2025-49747": {"file": "fake_eventhubs_cve.py", "func": "list_auth_rules"},
    "CVE-2025-49752": {"file": "fake_acr_cve.py", "func": "get_credentials"},
    "CVE-2025-53729": {"file": "fake_signalr_cve.py", "func": "list_keys"},
    "CVE-2025-53763": {"file": "fake_logicapps_cve.py", "func": "list_connections"},
    "CVE-2025-53767": {"file": "fake_batch_cve.py", "func": "list_pools"},
    "CVE-2025-53781": {"file": "fake_redis_ent_cve.py", "func": "extract_secrets_from_memory"},
    "CVE-2025-53792": {"file": "fake_functions2_cve.py", "func": "get_master_keys"},
    "CVE-2025-53793": {"file": "fake_cdn_cve.py", "func": "get_origin_credentials"},
    "CVE-2025-54914": {"file": "fake_firewall_cve.py", "func": "get_firewall_keys"},
    "CVE-2025-55316": {"file": "fake_dns_cve.py", "func": "config_endpoint"},
    "CVE-2025-55697": {"file": "fake_lb_cve.py", "func": "get_secrets"},
    "CVE-2025-58724": {"file": "fake_appgw_cve.py", "func": "waf_bypass"},
    "CVE-2025-59048": {"file": "fake_sentinel_cve.py", "func": "assume_role"},
    "CVE-2025-59247": {"file": "fake_purview_cve.py", "func": "get_asset_data"},
    "CVE-2025-59273": {"file": "fake_adf_cve.py", "func": "get_topic_keys"},
    "CVE-2025-59285": {"file": "fake_databricks_cve.py", "func": "list_secrets"},
    "CVE-2025-59291": {"file": "fake_containerapp_cve.py", "func": "get_secrets"},
    "CVE-2025-59292": {"file": "fake_springapp_cve.py", "func": "actuator_config_props"},
    "CVE-2025-59494": {"file": "fake_comms_cve.py", "func": "create_token"},
    "CVE-2025-59500": {"file": "fake_maps_cve.py", "func": "get_account_keys"},
    "CVE-2025-8069": {"file": "fake_devtest_cve.py", "func": "secrets"},
    "CVE-2026-1727": {"file": "fake_sphere_cve.py", "func": "dev_cert"},
}


def get_flag(cve_id: str) -> str:
    return f"FLAG{{{cve_id}_pwned}}"


def find_function_body(content: str, func_name: str):
    """Find the start and end of a function body."""
    pattern = rf'^([ \t]*)def {re.escape(func_name)}\([^)]*\):'
    match = re.search(pattern, content, re.MULTILINE)
    if not match:
        return None, None, None

    indent = match.group(1)
    func_start = match.end()

    # Find next function/class/decorator at same or lesser indent
    next_def = re.search(
        rf'^(?:{re.escape(indent)}(?:def |class |@)|(?!\s))',
        content[func_start + 1:],
        re.MULTILINE
    )
    if next_def:
        func_end = func_start + 1 + next_def.start()
    else:
        func_end = len(content)

    return func_start, func_end, indent


def inject_flag(cve_id: str, config: dict) -> tuple:
    """Inject flag into a lab file. Returns (success, message)."""
    cve_dir = os.path.join(LABS_DIR, cve_id)
    filepath = os.path.join(cve_dir, config["file"])

    if not os.path.exists(filepath):
        return False, f"File not found: {filepath}"

    with open(filepath, 'r') as f:
        content = f.read()

    flag = get_flag(cve_id)

    # Already done?
    if flag in content:
        return True, "already has flag"

    func_name = config["func"]
    func_start, func_end, indent = find_function_body(content, func_name)

    if func_start is None:
        return False, f"Function '{func_name}' not found"

    func_body = content[func_start:func_end]

    # Strategy: Find return statements that contain jsonify or string responses
    # and inject flag into them

    # Try Strategy 1: jsonify with dict literal
    # Pattern: return jsonify({...})
    jsonify_matches = list(re.finditer(r'return\s+jsonify\(\{', func_body))
    if jsonify_matches:
        # Use the FIRST jsonify return (main response)
        m = jsonify_matches[0]
        insert_pos = func_start + m.end()
        # Insert flag as first key
        new_content = content[:insert_pos] + f'"exploit_flag": "{flag}", ' + content[insert_pos:]
        with open(filepath, 'w') as f:
            f.write(new_content)
        return True, f"injected into jsonify dict (func={func_name})"

    # Strategy 2: jsonify with variable - add flag field before return
    jsonify_var_matches = list(re.finditer(r'(\s+)(return\s+jsonify\((\w+)\))', func_body))
    if jsonify_var_matches:
        m = jsonify_var_matches[0]
        var_name = m.group(3)
        indent_str = m.group(1)
        insert_pos = func_start + m.start()
        flag_line = f'{indent_str}{var_name}["exploit_flag"] = "{flag}"\n'
        new_content = content[:insert_pos] + flag_line + content[insert_pos:]
        with open(filepath, 'w') as f:
            f.write(new_content)
        return True, f"injected before jsonify({var_name}) (func={func_name})"

    # Strategy 3: return jsonify([...]) - wrap in dict
    jsonify_list_matches = list(re.finditer(r'return\s+jsonify\(\[', func_body))
    if jsonify_list_matches:
        m = jsonify_list_matches[0]
        # Replace return jsonify([...]) with return jsonify({"exploit_flag": FLAG, "data": [...]})
        # This is complex, so just add a response header approach
        # Simpler: find the jsonify return line and modify
        ret_pos = func_start + m.start()
        # Find end of this return statement
        ret_line_end = content.index('\n', ret_pos)
        # Add flag via response header
        line_indent = re.match(r'\s*', content[ret_pos:]).group(0)
        # Replace the whole approach: add flag to the response
        # Just inject after the function def as a wrapper
        pass  # fall through to strategy 4

    # Strategy 4: String response (triple-quoted or regular)
    str_returns = list(re.finditer(r'return\s+("""[\s\S]*?""")', func_body))
    if str_returns:
        m = str_returns[0]
        # Find the closing """ and insert flag before it
        abs_start = func_start + m.start(1)
        # Find the actual closing triple quote (not the opening one)
        str_content = m.group(1)
        # Opening """ is at index 0-2, find closing """
        close_pos = str_content.rindex('"""')
        insert_pos = abs_start + close_pos
        new_content = content[:insert_pos] + f'\n{flag}\n' + content[insert_pos:]
        with open(filepath, 'w') as f:
            f.write(new_content)
        return True, f"injected into string response (func={func_name})"

    # Strategy 5: Return with format string or concatenation
    # Fallback: add the flag to the function's first return by making response a tuple with header
    # Actually simplest fallback: add a line that will make the flag appear

    # Find any return in the function
    any_returns = list(re.finditer(r'(\s+)return\s+', func_body))
    if any_returns:
        m = any_returns[0]
        ret_indent = m.group(1)
        insert_pos = func_start + m.start()

        # Check if it returns a dict/json-like thing
        after_return = func_body[m.end():]
        first_line = after_return.split('\n')[0].strip()

        if first_line.startswith('{') or 'json' in first_line.lower():
            # It's returning a dict-like thing - add flag before return
            flag_line = f'{ret_indent}# CVE exploit verification\n'
            new_content = content[:insert_pos] + flag_line + content[insert_pos:]
            with open(filepath, 'w') as f:
                f.write(new_content)
            # This didn't add the flag to response... try another way

        # Ultimate fallback: Modify the return to include flag in response
        # Add response.headers approach
        pass

    # Strategy 6: Nuclear option - add a new endpoint /<cve_id>/flag that returns
    # the flag when the exploit endpoint is accessed first
    # But this changes behavior... let's try adding flag to the /env endpoint if nothing else works

    # Final fallback: Add flag as comment in the most sensitive looking return
    # Find any return with sensitive data keywords
    for ret_match in re.finditer(r'return\s+', func_body):
        after = func_body[ret_match.end():ret_match.end()+500]
        if any(kw in after.lower() for kw in ['password', 'secret', 'key', 'token', 'credential']):
            # Found a return with sensitive data
            abs_pos = func_start + ret_match.end()
            # If it starts with jsonify({
            if after.lstrip().startswith('jsonify({'):
                brace_pos = content.index('{', abs_pos)
                new_content = content[:brace_pos+1] + f'"exploit_flag": "{flag}", ' + content[brace_pos+1:]
                with open(filepath, 'w') as f:
                    f.write(new_content)
                return True, f"injected into sensitive jsonify (func={func_name})"
            break

    return False, f"Could not find suitable injection point in '{func_name}'"


def verify_all_flags():
    """Verify all flags are accessible."""
    results = {"ok": 0, "missing": 0, "errors": []}
    for cve_id in sorted(CVE_EXPLOIT_MAP.keys()):
        config = CVE_EXPLOIT_MAP[cve_id]
        filepath = os.path.join(LABS_DIR, cve_id, config["file"])
        flag = get_flag(cve_id)
        if os.path.exists(filepath):
            with open(filepath) as f:
                if flag in f.read():
                    results["ok"] += 1
                else:
                    results["missing"] += 1
                    results["errors"].append(cve_id)
        else:
            results["missing"] += 1
            results["errors"].append(f"{cve_id} (file missing)")
    return results


def main():
    print(f"Injecting flags into {len(CVE_EXPLOIT_MAP)} CVE labs...")
    print(f"Labs dir: {LABS_DIR}\n")

    success = 0
    failed = 0
    failed_list = []

    for cve_id in sorted(CVE_EXPLOIT_MAP.keys()):
        config = CVE_EXPLOIT_MAP[cve_id]
        ok, msg = inject_flag(cve_id, config)
        status = "OK" if ok else "FAIL"
        print(f"  [{status}] {cve_id}: {msg}")
        if ok:
            success += 1
        else:
            failed += 1
            failed_list.append((cve_id, msg))

    print(f"\n{'='*60}")
    print(f"Results: {success} success, {failed} failed out of {len(CVE_EXPLOIT_MAP)}")

    if failed_list:
        print(f"\nFailed labs:")
        for cve_id, msg in failed_list:
            print(f"  {cve_id}: {msg}")

    # Verify
    print(f"\nVerification:")
    v = verify_all_flags()
    print(f"  Flags present: {v['ok']}/{len(CVE_EXPLOIT_MAP)}")
    if v['errors']:
        print(f"  Missing: {v['errors']}")

    # Generate flag registry for metrics script
    registry = {}
    for cve_id in sorted(CVE_EXPLOIT_MAP.keys()):
        registry[cve_id] = get_flag(cve_id)

    registry_path = os.path.join(os.path.dirname(LABS_DIR), "cve_flags.json")
    with open(registry_path, 'w') as f:
        json.dump(registry, f, indent=2)
    print(f"\nFlag registry saved to: {registry_path}")


if __name__ == "__main__":
    main()
