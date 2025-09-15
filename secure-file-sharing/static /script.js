function confirmDelete(name){return confirm("Are you sure you want to delete: " + name + " ?")}
window.addEventListener('DOMContentLoaded', () => { const t = document.getElementById('toast'); if (t) setTimeout(()=> t.style.display = 'none', 3500); });
