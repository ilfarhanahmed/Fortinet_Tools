import paramiko
import getpass
import time

USERNAME = "admin-rebuild"
PASSWORD = getpass.getpass("SSH password: ")

# Read FAZ IPs
with open("faz_hosts.txt") as f:
    hosts = [line.strip() for line in f if line.strip()]

for host in hosts:

    print(f"\n[{host}] Connecting...")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh.connect(
            host,
            username=USERNAME,
            password=PASSWORD,
            timeout=10
        )

        print(f"[{host}] Connected")

        shell = ssh.invoke_shell()
        time.sleep(1)

        # Clear initial CLI output
        if shell.recv_ready():
            shell.recv(65535)

        # Run rebuild command
        shell.send("execute sql-local rebuild-db\n")
        time.sleep(2)

        output = shell.recv(65535).decode()
        print(output)

        # Confirm rebuild
        if "(y/n)" in output.lower():
            print(f"[{host}] Starting DB rebuild...")
            shell.send("y\n")
            time.sleep(2)
            print(f"[{host}] Rebuild triggered")

        else:
            print(f"[{host}] Confirmation prompt not found")

        ssh.close()

    except Exception as e:
        print(f"[{host}] ERROR: {e}")

print("\nDone.")