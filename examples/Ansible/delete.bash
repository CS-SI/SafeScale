for num in {1..4}
do
    (safescale host delete cluster-node-$num)&
done
wait
sleep 10
safescale network delete cluster-net