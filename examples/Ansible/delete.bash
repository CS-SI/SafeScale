for num in {1..4} 
do
    (broker host delete cluster-node-$num)&
done
wait
sleep 10
broker network delete cluster-net