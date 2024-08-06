function updateStatus(type, id, ip) {
    fetch(`/ping_status/${ip}`)
        .then(response => response.json())
        .then(data => {
            const statusElement = document.getElementById(`${type}-${id}-status`);
            const latencyElement = document.getElementById(`${type}-${id}-latency`);

            if (data.status === 'online') {
                statusElement.textContent = 'Online';
                statusElement.className = 'status-online';
                latencyElement.textContent = `${data.latency} ms`;
            } else {
                statusElement.textContent = 'Offline';
                statusElement.className = 'status-offline';
                latencyElement.textContent = '';
            }
        })
        .catch(error => {
            console.error('Error fetching ping status:', error);
        });
}

document.addEventListener('DOMContentLoaded', () => {
    const routers = document.querySelectorAll('#routers .list-group-item');
    routers.forEach(router => {
        const id = router.querySelector('span').id.split('-')[1];
        const ip = router.querySelector('span').previousSibling.textContent.split(' - ')[1];
        updateStatus('router', id, ip);
    });

    const servers = document.querySelectorAll('#servers .list-group-item');
    servers.forEach(server => {
        const id = server.querySelector('span').id.split('-')[1];
        const ip = server.querySelector('span').previousSibling.textContent.split(' - ')[1];
        updateStatus('server', id, ip);
    });
});
