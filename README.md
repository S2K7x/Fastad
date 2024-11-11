# fastad.py - Ultimate AD Domain Creation Script

`fastad.py` is a Python script that helps you automate the creation of Active Directory (AD) domains by generating customizable PowerShell commands. It simplifies the process of setting up new domains or joining existing ones, with options for configuring forests, domain functional levels, DNS settings, replication types, Organizational Units (OUs), user accounts, and more.

This script is ideal for system administrators and IT professionals who want to automate the process of setting up an Active Directory environment on Windows Server.

## Features

- **Create a New Forest or Join an Existing Domain**  
- **Customize Forest and Domain Functional Levels**  
- **Configure DNS Settings and Forwarders**  
- **Enable Global Catalog and Replication Options**  
- **Create Active Directory Sites and Subnets**  
- **Generate Organizational Units (OUs)**  
- **Create Initial Users and Groups**  
- **Set Up Domain Trust Relationships**  
- **Save PowerShell Commands to a `.ps1` File**  

## Requirements

- Python 3.x or higher
- PowerShell installed on a Windows Server environment (where the PowerShell commands will be executed)

## Installation

1. Clone the repository or download the `fastad.py` script.
2. Ensure you have Python 3.x installed on your machine.
3. Ensure your environment has the necessary permissions to run PowerShell commands on a Windows Server.

## Usage

### Running the Script

To run the script, open a terminal or command prompt and execute the following command:

```bash
python fastad.py
```

The script will prompt you for the necessary inputs to generate the PowerShell commands.

### User Inputs

The script will prompt you to provide the following information:

1. **Domain Information**
   - Fully Qualified Domain Name (e.g., `contoso.local`)
   - NetBIOS Name (e.g., `CONTOSO`)
   - Directory Services Restore Mode (DSRM) Password

2. **Domain and Forest Configuration**
   - Create a new forest or join an existing domain
   - DNS delegation (Yes/No)
   - Global Catalog (Yes/No)
   - Forest and Domain Functional Levels (choose from 2008, 2012, 2016, or 2019)
   - Replication Options (None, Full, Read-Only)

3. **Paths**
   - Active Directory Database Path (default: `C:\Windows\NTDS`)
   - Active Directory Log Files Path (default: `C:\Windows\NTDS`)
   - SYSVOL Path (default: `C:\Windows\SYSVOL`)

4. **Advanced Options**
   - Configure Active Directory Sites and Subnets (Yes/No)
   - Create Organizational Units (Yes/No)
   - Create Initial Users and Groups (Yes/No)
   - Set Up Trust Relationships (Yes/No)

5. **DNS Forwarders**
   - Optional: Enter DNS forwarders (comma-separated IPs, e.g., `8.8.8.8,1.1.1.1`)

### Saving the Commands

Once the script has gathered all the necessary inputs, it will generate the corresponding PowerShell commands. You will then have the option to save the generated commands to a `.ps1` file.

```bash
Would you like to save these commands to a file? (y/n):
```

If you choose **yes**, the script will save the commands in a file named `create_ad_domain.ps1`.

### Example Output

```powershell
# Install the Active Directory Domain Services feature
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote the server to a domain controller and create a new forest
Install-ADDSForest `
    -DomainName "contoso.local" `
    -DomainNetbiosName "CONTOSO" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "YourPassword" -AsPlainText -Force) `
    -InstallDNS `
    -CreateDnsDelegation $false `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -ForestMode "2016" `
    -DomainMode "2016"

# Configure DNS forwarders
Set-DnsServerForwarder -IPAddress "8.8.8.8","1.1.1.1"

# Configure AD Sites and Subnets
New-ADReplicationSite -Name "Default-First-Site-Name"
New-ADReplicationSubnet -Name "192.168.1.0/24" -Site "Default-First-Site-Name"

# Create Organizational Units (OUs)
New-ADOrganizationalUnit -Name "Sales" -Path "DC=contoso,DC=local"
New-ADOrganizationalUnit -Name "IT" -Path "DC=contoso,DC=local"

# Create initial user accounts
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@contoso.local" -Path "OU=IT,DC=contoso,DC=local" -AccountPassword (ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force) -Enabled $true
# Create initial group
New-ADGroup -Name "IT Group" -SamAccountName "ITGroup" -GroupScope Global -Path "OU=IT,DC=contoso,DC=local"

# Create a trust relationship with another domain
New-ADTrust -Name "trusteddomain.local" -Direction Bidirectional -Forest $true -TrustType External
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

If you'd like to contribute to the development of this script, feel free to fork the repository and submit a pull request. We welcome contributions to improve the functionality and flexibility of the script.

## Issues

If you encounter any issues or have feature requests, please open an issue on the [GitHub Issues](https://github.com/S2K7x/fastad/issues) page.

## Contact

For more information or questions, feel free to reach out to the project maintainer.
