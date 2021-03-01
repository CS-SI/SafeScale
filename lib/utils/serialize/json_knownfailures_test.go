// +build alltests

package serialize

func TestNestedLocksWithWritesDanger(t *testing.T) {
	PropertyTypeRegistry.Register("clusters", "first", &LikeFeatures{})
	PropertyTypeRegistry.Register("clusters", "second", &LikeFeatures{})

	clusters, _ := NewJSONProperties("clusters")
	assert.NotNil(t, clusters)

	task, _ := concurrency.NewUnbreakableTask()

	xerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
		thing := clonable.(*LikeFeatures)
		thing.Installed["Loren"] = "Ipsum"
		return nil
	})
	assert.Nil(t, xerr)

	// Here ve have clusters with "Ipsum", good
	// one at a time ??

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		oerr := clusters.Alter(task, "first", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got first lock")
			time.Sleep(50 * time.Millisecond)
			return clusters.Inspect(task, "second", func(clonable data.Clonable) fail.Error {
				other := clonable.(*LikeFeatures)
				other.Installed["elit"] = "In"
				fmt.Println("Two locks here")
				return nil
			})
		})
		assert.Nil(t, oerr)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
		oerr := clusters.Alter(task, "second", func(clonable data.Clonable) fail.Error {
			thing := clonable.(*LikeFeatures)
			thing.Installed["consectur"] = "adipiscing"
			fmt.Println("Got second lock")
			time.Sleep(50 * time.Millisecond)
			return clusters.Inspect(task, "first", func(clonable data.Clonable) fail.Error {
				other := clonable.(*LikeFeatures)
				other.Installed["elit"] = "In"
				fmt.Println("Two locks")
				return nil
			})
		})
		assert.Nil(t, oerr)
	}()

	failed := waitTimeout(&wg, 5*time.Second)
	if failed { // It ended with a deadlock
		t.Fail()
	}
}
