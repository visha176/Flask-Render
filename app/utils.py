import subprocess

def ping(host):
    """
    Returns True if host responds to a ping request
    """
    command = ['ping', '-c', '1', host]
    return subprocess.run(command, capture_output=True).returncode == 0

def ping_latency(host):
    """
    Returns the latency (ping time in ms) to the host
    """
    command = ['ping', '-c', '1', host]
    proc = subprocess.run(command, capture_output=True, text=True)
    if proc.returncode == 0:
        output = proc.stdout
        # Extract the ping time from the output
        if 'time=' in output:
            latency = output.split('time=')[1].split(' ')[0]
            return float(latency.replace('ms', ''))
        return None
    else:
        return None
