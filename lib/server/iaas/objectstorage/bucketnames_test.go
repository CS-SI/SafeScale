package objectstorage

import "testing"

func TestBuildMetadataBucketName(t *testing.T) {
	type args struct {
		driver  string
		region  string
		domain  string
		project string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"first", args{
			driver:  "a",
			region:  "b",
			domain:  "c",
			project: "d",
		}, "0.safescale-449a7986e14ff78da8c3053229f4f1d2", false},
		{"second", args{
			driver:  "a",
			region:  "c",
			domain:  "b",
			project: "d",
		}, "0.safescale-39aa5fec414ff78da8c3028953851096", false},
		{"second insensitive", args{
			driver:  "a",
			region:  "c",
			domain:  "b",
			project: "D",
		}, "0.safescale-39aa5fec414ff78da8c3028953851096", false},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildMetadataBucketName(tt.args.driver, tt.args.region, tt.args.domain, tt.args.project)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildMetadataBucketName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BuildMetadataBucketName() got = %v, want %v", got, tt.want)
			}
		})
	}
}