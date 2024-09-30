import socket
import time
import asyncio
from django.shortcuts import render
from .forms import PortScanForm
from .ports import common_ports
from django.http import HttpResponse

# Asynchronous function to scan ports
async def scan_ports_async(target, port_range, log_function):
    open_ports = []
    for port in port_range:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                log_function(f"Scanning port {port}... Port is open")
            sock.close()
        except (socket.timeout, socket.error, ConnectionRefusedError) as e:
            log_function(f"Error scanning port {port}: {str(e)}")
        time.sleep(0.1)  # Delay to avoid overwhelming the network
        log_function(f"<script>portScanned();</script>")
    return open_ports

# Helper function to log messages
def log_to_console(text, logs):
    logs.append(text)

# View to handle port scanning
def port_scan_view(request):
    form = PortScanForm()
    result = None
    logs = []
    
    if request.method == 'POST':
        form = PortScanForm(request.POST)
        if form.is_valid():
            target_host = form.cleaned_data['target']
            # Create an asyncio event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            num_chunks = 4
            chunk_size = len(common_ports) // num_chunks
            chunks = [common_ports[i:i + chunk_size] for i in range(0, len(common_ports), chunk_size)]
            log_to_console("Scanning started...", logs)
            tasks = [scan_ports_async(target_host, chunk, lambda x: log_to_console(x, logs)) for chunk in chunks]
            results = loop.run_until_complete(asyncio.gather(*tasks))
            open_ports = [port for result in results for port in result]

            # Store the open ports in the session
            request.session['open_ports'] = open_ports

            if open_ports:
                result = "Open ports: " + ", ".join(map(str, open_ports))
                log_to_console(f"Scan completed. Open ports: {', '.join(map(str, open_ports))}", logs)
            else:
                result = "No open ports found."
                log_to_console("Scan completed. No open ports found.", logs)

    return render(request, 'scanner/index.html', {'form': form, 'result': result, 'logs': logs})

# Function to export scan results
def export_results(request):
    # Retrieve open ports from session
    open_ports = request.session.get('open_ports', [])
    
    if open_ports:
        scan_results = "Open Ports:\n" + "\n".join(map(str, open_ports))
    else:
        scan_results = "No open ports found."
    
    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="scan_results.txt"'
    response.write(scan_results)
    
    return response
