document.addEventListener('DOMContentLoaded', function() {
    const topoFileSelect = document.getElementById('topo_file');
    const commandLinks = document.querySelectorAll('.sidebar ul li a');

    topoFileSelect.addEventListener('change', function() {
        if (topoFileSelect.value) {
            commandLinks.forEach(link => link.classList.remove('disabled'));
        }
    });
});