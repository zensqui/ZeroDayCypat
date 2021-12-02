const fs = require("fs")

//for each file in ./pullCMD run a function
fs.readdir("./pullCMD", (err, files) => {
	for (const file of files) {
        fs.readFile("./pullCMD/" + file, "utf8", (err, data) => {
            data.split("\n").forEach(line => {
                if (line.toLowerCase().startsWith("powershell")) {
                    
                }
            })
        })
	}
})
