//go:build !linux

package classify

import "syscall"

// markControl — заглушка вне Linux.
//
// SO_MARK — часть сетевого стека Linux (netfilter/conntrack), физически
// отсутствует на других платформах. Сборка на macOS/BSD (стенд разработки,
// `sh scripts/check.sh`) не должна на этом падать, но и молчать про
// неспособность пометить зонд нельзя: для вызывающего (once, §5.5) провал и
// отсутствие возможности — одно и то же наблюдение, «зонд ушёл немеченым», и
// оно обязано снизить достоверность вердикта так же, как настоящий провал
// SO_MARK на Linux.
func markControl(_ uint32, ok *bool) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		*ok = false
		return nil
	}
}
