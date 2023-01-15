package ldapcpp

type Logger interface {
	Debug(msg string)

	Error(msg string)
}
