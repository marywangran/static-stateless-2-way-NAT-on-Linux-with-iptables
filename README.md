static-stateless-2-way-NAT-on-Linux-with-iptables
=================================================

perform a static stateless 2-way NAT with iptables 


如果你在寻找Linux上配置诸如Cisco设备上的static双向NAT的方法，这个或许就是你想要的；

what？你觉得它完不成PAT？是的，它不行。但是想做PAT为何不使用现有的iptables实现呢？它可以自动为你解决元组唯一性问题。不要从概念上分析，事实上，static双向NAT是完全对称的，一对一的
，也只有在BOX两边的网络在拓扑级别是完全对等的情形下，这种NAT或许才是有用的，Cisco设备经常处在这样的位置，比如一个很大的stub节点的出口位置，比如两个domain的中间位置...

我将名字取为STATIC-2-WAY-NAT，比较长也比较怪，完全不符合UNIX的小写短名传统，我的想法是：这样可以少写很多的帮助信息，因为名字就是自解释的。
