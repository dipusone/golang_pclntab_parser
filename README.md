## Why did fork have a new project?

This project originally existed as the pr of the original project, and several bug were fixed when I submitted the pr. When the original author accepts the fork, I will delete the project, otherwise it will exist forever.

# GoLang binary parser
Author: **Jacopo Ferrigno**

_BinaryNinja plugin to parse GoLang binaries and restore some information, like function names and type information._

## Description:

This plugin will parse a go binary and restore some information like:
- Function names by parsing the `.gopclntab` section in the binary. If there is no section named .gopclntab it will try to search for it.
- Comment the function with the filename from which the function comes
- Print the list of files in the binary
- Recover type information and names by parsing specific callsites gopclntab.

The plugin works for all GoLang version from 12 to 119.

## References

The plugin is based on the following resources.

	https://github.com/f0rki/bn-goloader
	https://go.dev/src/debug/gosym/pclntab.go
	https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub
	https://securelist.com/extracting-type-information-from-go-binaries/104715/
	https://github.com/golang/go/blob/fad4a16fd43f6a72b6917eff656be27522809074/src/reflect/type.go#L317


## License

This plugin is released under an [MIT license](./license).

