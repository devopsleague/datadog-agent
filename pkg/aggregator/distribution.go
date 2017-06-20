package aggregator

// Distribution tracks the distribution of samples added over one flush
// period. Designed to be globally accurate for percentiles.
type Distribution struct {
	sketch QSketch
	count  int64
}

// NewDistribution creates a new Distribution
func NewDistribution() *Distribution {
	return &Distribution{sketch: NewQSketch()}
}

func (d *Distribution) addSample(sample *MetricSample, timestamp int64) {
	// Insert sample value into the sketch
	d.sketch.Add(sample.Value)
	d.count++
}

func (d *Distribution) flush(timestamp int64) (*SketchSerie, error) {
	if d.count == 0 {
		return &SketchSerie{}, NoSketchError{}
	}
	// compress the sketch before flushing
	d.sketch.Compress()
	sketch := &SketchSerie{
		Sketches: []Sketch{{Timestamp: timestamp,
			Sketch: d.sketch}},
	}
	// reset the global histogram
	d.sketch = NewQSketch()
	d.count = 0

	return sketch, nil
}
