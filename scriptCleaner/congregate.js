//! make go through all files in ./congregateBat

const fs = require("fs")

var fileString = fs.readFileSync(__dirname + "/main.bat", "utf8")

var fileArray = fileString.split("\n")
var markToDelete = []
var finalArray = []

//
for (var i = 0; i < fileArray.length; i++) {
	//remove all conditionals
	if (fileArray[i].toLowerCase().trim().startsWith("if ")) {
		markToDelete.push(i)
		var open = 0
		var closed = 0
		for (var j = i; j < fileArray.length; j++) {
			if (fileArray[j].includes("(")) {
				open++
			}
			if (fileArray[j].includes(")")) {
				closed++
			}
			if (open == closed) {
				markToDelete.push(j)
				break
			}
		}
	}

	//remove all comments/echos
	if (fileArray[i].toLowerCase().trim().startsWith("echo")) {
		markToDelete.push(i)
	}
	if (fileArray[i].toLowerCase().trim().startsWith("::") || fileArray[i].toLowerCase().trim().startsWith("rem")) {
		markToDelete.push(i)
    }
    
    
}

for (var i = 0; i < fileArray.length; i++) {}

//doesn't have duplicate line numbers
var filteredMarked = new Set(markToDelete)

for (var i = 0; i < fileArray.length; i++) {
	if (!filteredMarked.has(i)) {
		finalArray.push(fileArray[i])
	}
}

fs.writeFileSync(__dirname + "/out.bat", finalArray.join("\n"))
