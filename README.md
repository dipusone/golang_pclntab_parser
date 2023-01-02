# GoLang pclntab parser
Author: **Jacopo Ferrigno**

_BinaryNinja plugin to parse gopclntab and restore functions names for all GoLang versions._

## Description:

This plugin will parse the gopclntab and restore the function names extracting the information from the `.gopclntab` section in the binary. If there is no section named .gopclntab it will try to search for the section.

It will also try to recover type information and restore them

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
