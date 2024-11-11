import os
import getpass

def print_instructions():
    print("\nWelcome to the Ultimate AD Domain Creation Script!")
    print("This Python script will generate highly customizable PowerShell commands for creating an Active Directory domain.")
    print("You can personalize forest and domain creation, set functional levels, configure sites, and much more!\n")

def validate_input(prompt, valid_options):
    """ Helper function to validate user input against a list of valid options """
    while True:
        user_input = input(prompt).lower()
        if user_input in valid_options:
            return user_input
        print(f"Invalid input. Please choose from: {', '.join(valid_options)}.")

def get_user_input():
    # Basic domain information
    domain_name = input("Enter the fully qualified domain name (e.g., contoso.local): ")
    netbios_name = input("Enter the NetBIOS name (e.g., CONTOSO): ")

    # Securely handle password input (hides input while typing)
    safe_mode_password = getpass.getpass("Enter the Directory Services Restore Mode (DSRM) password: ")

    # Customization options with input validation
    forest_or_domain = validate_input("Are you creating a new forest or joining an existing domain? (new/join): ", ["new", "join"])
    dns_delegation = validate_input("Do you want DNS delegation (Yes/No)? ", ["yes", "no"]) == "yes"
    global_catalog = validate_input("Do you want this server to be a Global Catalog? (Yes/No): ", ["yes", "no"]) == "yes"
    forest_functional_level = validate_input("Select the forest functional level (2008, 2012, 2016, 2019): ", ["2008", "2012", "2016", "2019"])
    domain_functional_level = validate_input("Select the domain functional level (2008, 2012, 2016, 2019): ", ["2008", "2012", "2016", "2019"])
    replication_options = validate_input("Specify replication type (None, Full, Read-Only): ", ["none", "full", "read-only"])

    # Advanced options with default paths and checks
    db_path = input("Enter the path to the Active Directory database (e.g., C:\\Windows\\NTDS) [Press Enter for default]: ") or "C:\\Windows\\NTDS"
    log_path = input("Enter the path to the AD log files (e.g., C:\\Windows\\NTDS) [Press Enter for default]: ") or "C:\\Windows\\NTDS"
    sysvol_path = input("Enter the path to the SYSVOL folder (e.g., C:\\Windows\\SYSVOL) [Press Enter for default]: ") or "C:\\Windows\\SYSVOL"

    # More advanced features
    configure_sites = validate_input("Do you want to configure Active Directory sites and subnets? (Yes/No): ", ["yes", "no"]) == "yes"
    configure_ous = validate_input("Do you want to create Organizational Units (OUs)? (Yes/No): ", ["yes", "no"]) == "yes"
    configure_users = validate_input("Do you want to create initial users and groups? (Yes/No): ", ["yes", "no"]) == "yes"
    configure_trusts = validate_input("Do you want to configure domain trusts? (Yes/No): ", ["yes", "no"]) == "yes"

    # Extra feature: DNS Forwarders configuration
    dns_forwarders = input("Enter DNS forwarders (comma-separated IPs, e.g., 8.8.8.8,1.1.1.1) [Press Enter to skip]: ")

    return {
        "domain_name": domain_name,
        "netbios_name": netbios_name,
        "safe_mode_password": safe_mode_password,
        "forest_or_domain": forest_or_domain,
        "dns_delegation": dns_delegation,
        "global_catalog": global_catalog,
        "forest_functional_level": forest_functional_level,
        "domain_functional_level": domain_functional_level,
        "replication_options": replication_options,
        "db_path": db_path,
        "log_path": log_path,
        "sysvol_path": sysvol_path,
        "configure_sites": configure_sites,
        "configure_ous": configure_ous,
        "configure_users": configure_users,
        "configure_trusts": configure_trusts,
        "dns_forwarders": dns_forwarders
    }

def generate_powershell_commands(user_input):
    # Base PowerShell command for installing AD
    commands = '''
# Install the Active Directory Domain Services feature
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
'''

    # Handle new forest or joining an existing domain
    if user_input['forest_or_domain'] == "new":
        commands += f'''
# Promote the server to a domain controller and create a new forest
Install-ADDSForest `
    -DomainName "{user_input['domain_name']}" `
    -DomainNetbiosName "{user_input['netbios_name']}" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "{user_input['safe_mode_password']}" -AsPlainText -Force) `
    -InstallDNS `
    -CreateDnsDelegation {"$true" if user_input['dns_delegation'] else "$false"} `
    -DatabasePath "{user_input['db_path']}" `
    -LogPath "{user_input['log_path']}" `
    -SysvolPath "{user_input['sysvol_path']}" `
    -ForestMode "{user_input['forest_functional_level']}" `
    -DomainMode "{user_input['domain_functional_level']}" '''
    else:
        commands += f'''
# Join an existing domain and promote the server to a domain controller
Install-ADDSDomainController `
    -DomainName "{user_input['domain_name']}" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "{user_input['safe_mode_password']}" -AsPlainText -Force) `
    -InstallDNS `
    -CreateDnsDelegation {"$true" if user_input['dns_delegation'] else "$false"} `
    -DatabasePath "{user_input['db_path']}" `
    -LogPath "{user_input['log_path']}" `
    -SysvolPath "{user_input['sysvol_path']}" '''

    # Add Global Catalog option
    if user_input['global_catalog']:
        commands += " `\n    -GlobalCatalog"

    # Add replication options
    if user_input['replication_options'] == "none":
        commands += " `\n    -NoReplication"
    elif user_input['replication_options'] == "read-only":
        commands += " `\n    -ReadOnlyReplica"

    # Configure DNS forwarders
    if user_input['dns_forwarders']:
        forwarders = ','.join(f'"{ip}"' for ip in user_input['dns_forwarders'].split(','))
        commands += f'''
# Configure DNS forwarders
Set-DnsServerForwarder -IPAddress {forwarders}
'''

    # Configuration for AD Sites (if chosen)
    if user_input['configure_sites']:
        commands += '''
# Configure AD Sites and Subnets
New-ADReplicationSite -Name "Default-First-Site-Name"
New-ADReplicationSubnet -Name "192.168.1.0/24" -Site "Default-First-Site-Name"
'''

    # Configuration for OUs (if chosen)
    if user_input['configure_ous']:
        commands += f'''
# Create Organizational Units (OUs)
New-ADOrganizationalUnit -Name "Sales" -Path "DC={user_input['domain_name'].split('.')[0]},DC={user_input['domain_name'].split('.')[1]}"
New-ADOrganizationalUnit -Name "IT" -Path "DC={user_input['domain_name'].split('.')[0]},DC={user_input['domain_name'].split('.')[1]}"
'''

    # Create initial users and groups (if chosen)
    if user_input['configure_users']:
        commands += f'''
# Create initial user accounts
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@{user_input['domain_name']}" -Path "OU=IT,DC={user_input['domain_name'].split('.')[0]},DC={user_input['domain_name'].split('.')[1]}" -AccountPassword (ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force) -Enabled $true
# Create initial group
New-ADGroup -Name "IT Group" -SamAccountName "ITGroup" -GroupScope Global -Path "OU=IT,DC={user_input['domain_name'].split('.')[0]},DC={user_input['domain_name'].split('.')[1]}"
'''

    # Add trust relationships (if chosen)
    if user_input['configure_trusts']:
        commands += '''
# Create a trust relationship with another domain
New-ADTrust -Name "trusteddomain.local" -Direction Bidirectional -Forest $true -TrustType External
'''

    commands += "\n\n# Once the server is promoted, it will restart to apply changes"

    return commands

def main():
    print_instructions()
    
    # Get user input
    user_input = get_user_input()
    
    # Generate the PowerShell commands
    ps_commands = generate_powershell_commands(user_input)
    
    # Output the PowerShell commands for the user
    print("\nThe following PowerShell commands have been generated:\n")
    print(ps_commands)
    
    # Optionally, write the commands to a .ps1 file for the user
    save_option = input("Would you like to save these commands to a file? (y/n): ")
    if save_option.lower() == 'y':
        with open("create_ad_domain.ps1", "w") as f:
            f.write(ps_commands)
        print("\nCommands have been saved to 'create_ad_domain.ps1'.")

if __name__ == "__main__":
    main()
