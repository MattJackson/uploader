for (const b of document.querySelectorAll('button[data-link]')) {
	b.addEventListener('click', async () => {
		await navigator.clipboard.writeText(location.origin + b.dataset.link)
		const was = b.textContent
		b.textContent = 'Copied ✓'
		setTimeout(() => (b.textContent = was), 1500)
	})
}
for (const f of document.querySelectorAll('form[data-confirm]')) {
	f.addEventListener('submit', (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault() })
}
