package controller

import "fmt"

// idPool hands out small integer ids for names. Freed ids go to the back of a
// queue and are reused last, because conntrack entries in the kernel may still
// point at an old backend id for a while.
type idPool struct {
	max   int
	byKey map[string]uint32
	next  uint32
	freed []uint32
}

func newIDPool(max int) idPool {
	return idPool{max: max, byKey: map[string]uint32{}}
}

func (p *idPool) get(name string) (uint32, error) {
	if id, ok := p.byKey[name]; ok {
		return id, nil
	}
	var id uint32
	switch {
	case int(p.next) < p.max:
		id = p.next
		p.next++
	case len(p.freed) > 0:
		id = p.freed[0]
		p.freed = p.freed[1:]
	default:
		return 0, fmt.Errorf("out of ids (max %d)", p.max)
	}
	p.byKey[name] = id
	return id, nil
}

// adopt reserves an id that already exists elsewhere (restored state). ids
// below it that nobody holds stay unused until the pool wraps.
func (p *idPool) adopt(name string, id uint32) {
	p.byKey[name] = id
	if id >= p.next {
		p.next = id + 1
	}
}

func (p *idPool) lookup(name string) (uint32, bool) {
	id, ok := p.byKey[name]
	return id, ok
}

func (p *idPool) release(name string) {
	id, ok := p.byKey[name]
	if !ok {
		return
	}
	delete(p.byKey, name)
	p.freed = append(p.freed, id)
}
