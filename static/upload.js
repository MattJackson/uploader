import { Uppy, Dashboard, Tus } from '/static/uppy.min.mjs'

const admin = document.body.dataset.admin === '1'
const uppy = new Uppy({ restrictions: { maxFileSize: 500 * 1024 ** 3 } })
	.use(Dashboard, {
		inline: true,
		target: '#drop',
		width: '100%',
		height: admin ? 300 : 420,
		theme: 'auto',
		proudlyDisplayPoweredByUppy: false,
		showProgressDetails: true,
		hideProgressAfterFinish: false,
	})
	// Chunked + resumable: if the connection drops, re-adding the same file
	// continues from the last chunk the server has.
	.use(Tus, {
		endpoint: '/files/',
		chunkSize: 64 * 1024 * 1024,
		retryDelays: [0, 1000, 3000, 5000, 10000, 20000, 30000, 60000],
		removeFingerprintOnSuccess: true,
	})

// admin.js won't auto-reload while files are staged, uploading or failed:
// a reload would drop them.
window.uploading = () => uppy.getFiles().some((f) => !f.progress.uploadComplete)

uppy.on('complete', (result) => {
	if (!result.successful.length || result.failed.length) return
	if (admin) {
		location.reload()
	} else {
		document.getElementById('done').hidden = false
	}
})
