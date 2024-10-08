# Linux Hardening System Script

This repository contains a shell script designed to evaluate and enhance the security configuration of Linux systems. Specifically, it checks compliance with security best practices on RHEL (Red Hat Enterprise Linux) and Debian-based distributions.

## Features

- **Password Policy Check**:
  - Verifies `pwquality` settings to ensure strong password policies.
  - Checks `pwhistory` to enforce password history requirements.

- **SSH Configuration Check**:
  - Analyzes `sshd_config` for adherence to best practices for secure SSH configurations.

- **Firewall Status Check**:
  - Checks if the firewall is running and properly configured.

## Requirements

- **Operating System**: RHEL or Debian-based distributions (e.g., Ubuntu).
- **Privileges**: The script requires root or sudo access to perform security checks.

## Usage

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/ThawThuHan/Linux_Harden_System.git
    ```

2. **Navigate to the Script Directory**:

    ```bash
    cd Linux_Harden_System
    ```

3. **Make the Script Executable**:

    ```bash
    chmod +x harden-system.sh
    ```

4. **Run the Script**:

    ```bash
    sudo ./harden-system.sh -h
    ```

## Script Details

- `harden-system.sh`: The main script file that performs the security checks described above.

  ![image](https://github.com/user-attachments/assets/8975937b-726f-4d5c-b704-1edb8bae4829)


## Example Output

Running the script will provide output indicating whether the system meets the specified security best practices. The results are presented in a readable format, detailing which aspects are compliant or require attention.

<img width="357" alt="Capture" src="https://github.com/user-attachments/assets/8c8ed89f-823a-4d9a-ad5e-5e413a4c9770">


## Contributing

If you have suggestions for improvements or would like to contribute to this project, please fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[Thaw Thu Han](https://github.com/ThawThuHan)
