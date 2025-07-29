# GoLang binary parser
Author: **Jacopo Ferrigno**

_BinaryNinja plugin to parse GoLang binaries and restore some information, like function names, type information and recover the user defined types._

## Description:

This plugin will parse a go binary and restore some information like:

- Function names by parsing the `.gopclntab` section in the binary. If there is no section named .gopclntab it will try to search for it.
- Recover the user defined Go types and de ones defined by the runtime
- Create the user defined/runtime defined Go types as `Types` in Binary Ninja
- Rename functions with their original name and organize them in containers
- Comment the function with the filename from which the function comes
- Print the list of files in the binary

The plugin works for all GoLang version from 12 to 124.

## References

The plugin is based on the following resources.

	https://github.com/f0rki/bn-goloader
	https://go.dev/src/debug/gosym/pclntab.go
	https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub
	https://securelist.com/extracting-type-information-from-go-binaries/104715/
	https://github.com/golang/go/blob/fad4a16fd43f6a72b6917eff656be27522809074/src/reflect/type.go#L317


## Contributors

- [ltlly](https://github.com/ltlly)

## License

This plugin is released under an [MIT license](./license).

