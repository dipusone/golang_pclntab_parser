# GoLang pclntab parser
Author: **Jacopo Ferrigno**

_BinaryNinja plugin to parse GoLang binaries and restore some information, like function names._

## Description:

This plugin will parse a go binary and restore some information like:
- Function names by parsing the `.gopclntab` section in the binary. If there is no section named .gopclntab it will try to search for it.
- Recover type information by parsing specific callsbuthe gopclntab and restore the function names extracting the information from the `.gopclntab` section in the binary.

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
