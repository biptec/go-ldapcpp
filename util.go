package ldapcpp

import "C"

func vector2slice(vector StringVector) []string {
	result := make([]string, vector.Size())
	for i := 0; i < int(vector.Size()); i++ {
		result[i] = vector.Get(i)
	}
	return result
}
