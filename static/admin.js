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

// Arriving: poll the server and redraw, with speed and ETA worked out from
// how fast the received bytes grow between polls.
const arriving = document.getElementById('arriving')
if (arriving) {
	const POLL = 2000, WINDOW = 15000, STALL = 30
	const samples = new Map() // id -> [{t, n}], newest last
	let known = new Map([...arriving.querySelectorAll('tr[data-id]')].map((r) => [r.dataset.id, r.querySelector('td.name').textContent]))
	let missed = 0, busy = false, reloadDue = false

	const size = (n) => {
		if (n < 1024) return n + ' B'
		let div = 1024, exp = 0
		for (let m = Math.floor(n / 1024); m >= 1024; m = Math.floor(m / 1024)) { div *= 1024; exp++ }
		return (n / div).toFixed(1) + ' ' + 'KMGTPE'[exp] + 'B'
	}
	const dur = (s) => {
		s = Math.max(0, Math.round(s))
		if (s < 60) return s + 's'
		if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's'
		if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm'
		return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h'
	}
	const ago = (s) => (s < 60 ? 'just now' : dur(s).split(' ')[0] + ' ago')

	// speed in bytes/s over the last WINDOW, or null until there's enough to say.
	const speed = (p, now) => {
		let s = samples.get(p.id) || []
		if (s.length && p.received < s[s.length - 1].n) s = [] // restarted from scratch
		if (p.idle >= STALL) s = [] // don't let a pause drag the average down later
		s.push({ t: now, n: p.received })
		while (s.length > 2 && now - s[1].t >= WINDOW) s.shift()
		samples.set(p.id, s)
		const first = s[0], last = s[s.length - 1]
		if (s.length < 2 || last.t - first.t < POLL / 2 || last.n === first.n) return null
		return ((last.n - first.n) * 1000) / (last.t - first.t)
	}

	const el = (tag, cls, text) => {
		const e = document.createElement(tag)
		if (cls) e.className = cls
		if (text != null) e.textContent = text
		return e
	}

	const row = (p, now) => {
		const tr = el('tr')
		tr.dataset.id = p.id
		const name = el('td', 'name', p.name || '(unnamed)')
		const meta = el('td', 'meta')
		const bar = el('progress')
		bar.max = 100
		bar.value = p.size ? Math.floor((p.received * 100) / p.size) : 100
		if (p.saving) {
			meta.textContent = size(p.size) + ' · saving to NAS…'
		} else {
			meta.textContent = size(p.received) + ' / ' + size(p.size) + ' · ' + bar.value + '%'
			const parts = []
			const bps = speed(p, now)
			if (p.idle >= STALL) {
				// Connected: the sender is there but nothing is moving. Not
				// connected: they've gone, and it waits for them to resume.
				const what = p.connected ? 'stalled · connected, no data for ' : 'disconnected · no data for '
				parts.push(el('span', 'stalled', what + dur(p.idle)))
			} else if (bps) {
				parts.push(size(Math.round(bps)) + '/s')
				parts.push('~' + dur((p.size - p.received) / bps) + ' left')
			} else {
				parts.push('measuring…')
			}
			if (p.ip) parts.push(p.ip)
			parts.push('started ' + ago(p.age))
			// One line each: progress and origin, browser, resumes.
			const lines = [parts]
			if (p.client) lines.push([p.client])
			if (p.resumes) lines.push(['resumed ' + p.resumes + '×'])
			for (const items of lines) {
				const line = el('span', 'detail')
				if (p.ua && items[0] === p.client) line.title = p.ua
				items.forEach((x, i) => {
					if (i) line.append(' · ')
					line.append(typeof x === 'string' ? el('span', 'part', x) : x)
				})
				name.append(line)
			}
		}
		const act = el('td', 'actions')
		if (!p.saving) {
			const f = el('form')
			f.method = 'post'
			f.action = '/admin/partial/delete'
			const id = el('input')
			id.type = 'hidden'
			id.name = 'id'
			id.value = p.id
			f.append(id, el('button', 'danger', 'Delete'))
			const msg = 'Delete the unfinished upload ' + (p.name || '(unnamed)') + '?' +
				(p.connected ? ' It is still being sent: this stops it.' : '')
			f.addEventListener('submit', (e) => { if (!confirm(msg)) e.preventDefault() })
			act.append(f)
		}
		act.append(bar)
		tr.append(name, meta, act)
		return tr
	}

	const poll = async () => {
		if (document.hidden || busy) return
		busy = true
		try {
			await refresh()
		} finally {
			busy = false
		}
	}

	const refresh = async () => {
		let rows
		try {
			const res = await fetch('/admin/arriving', { cache: 'no-store', redirect: 'manual' })
			if (!res.ok || !(res.headers.get('content-type') || '').includes('json')) throw new Error(res.status)
			rows = await res.json()
			missed = 0
		} catch {
			if (++missed === 3) arriving.querySelector('h2').textContent = 'Arriving (not updating — refresh the page)'
			return
		}
		const now = Date.now()
		const ids = new Set(rows.map((p) => p.id))
		for (const id of samples.keys()) if (!ids.has(id)) samples.delete(id)
		const fresh = rows.map((p) => row(p, now)) // always, so speed keeps sampling
		// Don't redraw under a selection: it would be lost (e.g. copying an IP).
		const sel = getSelection()
		if (!(sel && !sel.isCollapsed && arriving.contains(sel.anchorNode))) {
			arriving.querySelector('h2').textContent = 'Arriving'
			arriving.querySelector('tbody').replaceChildren(...fresh)
			arriving.hidden = rows.length === 0
		}
		// A file has landed on the NAS once its row is gone for good: an
		// upload's row normally turns into a "saving" one first. Reload to
		// list it under Received, once nothing else is still saving (one
		// reload per batch) and it can't drop files staged in our uploader.
		const saving = new Set(rows.filter((p) => p.saving).map((p) => p.name))
		for (const [id, name] of known) {
			if (!ids.has(id) && (id.startsWith('outbox/') || !saving.has(name))) reloadDue = true
		}
		known = new Map(rows.map((p) => [p.id, p.name]))
		if (reloadDue && saving.size === 0 && !(window.uploading && window.uploading())) location.reload()
	}

	const loop = async () => {
		await poll()
		setTimeout(loop, POLL)
	}
	document.addEventListener('visibilitychange', () => { if (!document.hidden) poll() })
	loop()
}
