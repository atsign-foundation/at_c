-- Anybody using the lazy package manager in nvim will have `.[c|cpp|h]template`
-- files act like their normal respective filetype in this project
vim.filetype.add({
	extension = {
		ctemplate = "c",
		cpptemplate = "cpp",
		htemplate = "cpp",
	},
})

return {}
