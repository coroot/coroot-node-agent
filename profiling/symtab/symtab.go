package symtab

type SymbolTable interface {
	Refresh()
	Cleanup()
	Resolve(addr uint64) Symbol
}

type SymbolNameResolver interface {
	Refresh()
	Cleanup()
	IsDead() bool
	Resolve(addr uint64) string
}

type noopSymbolNameResolver struct {
}

func (n *noopSymbolNameResolver) IsDead() bool {
	return false
}

func (n *noopSymbolNameResolver) Resolve(addr uint64) string {
	return ""
}

func (n *noopSymbolNameResolver) Refresh() {

}
func (n *noopSymbolNameResolver) Cleanup() {

}
