# Spark_Job_with_cluster_expand_triggered_by_Job.mp4

This video shows the submission of a complex workflow to Spark using a OGC WPS service, with dynamic up-scaling of the Spark cluster determined by
the needs the workflow identifies.

This workflow:

 - downloads Pleiade images under a region of interest passed into the WPS request using EODAG tool connected to Theia datasource
 - computes the necessary size of the Spark cluster in function of the number of images under the region of interest and the number of stereo tuples that can be done
 - triggers the cluster expansion accordingly to the needs
 - runs s2p processing on sub portion of the stereo tuples in each cluster node to produce point clouds
 - merges point clouds to into a digital elevation model under the region of interest.

The initial duration of the video is almost 3,5 hours; parts have been accelerated or cut to reduce the duration to 5 minutes
