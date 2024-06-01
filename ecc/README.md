### Windowed scalar mul using auxiliary generator

$$
\begin{align}
0 &~~~~~~~ 1: ~~~~~~~~~~ [2]P ~~ [3]P ~~ \cdots~\cdots ~~~ [2^w +1]P   \\ 
1 &~~~~~~ 2^w: ~~~~~~~~~ [2]P ~~ [3]P ~~ \cdots~\cdots ~~~ [2^w +1]P  \\
2  &~~~~ (2^w)^2: ~~~~~~ [2]P ~~ [3]P ~~ \cdots~\cdots ~~~ [2^w +1]P  \\
\cdots & \cdots \\ 
n-3 & ~~~~ (2^w)^{n-3}: ~~ [2]P ~~ [3]P ~~ \cdots~\cdots ~~~ [2^w +1]P \\ 
n-2 & ~~~~ (2^w)^{n-2}: ~~ [2]P ~~ [3]P ~~ \cdots~\cdots ~~~ [2^w +1]P  \\ 
n-1  & ~~~~ (2^w)^{n-1}: ~~ [2]P ~~ [3]P ~~ \cdots ~~~ [2^\ell +1]P \\
\end{align}
$$

where  window_size $w>1$ and scalar_size $= w(n-1) + \ell$ with $1\leq \ell \leq w$.

The scalar $k\in F_r$ can be adjusted upfront $k' = k - (2*\sum_{0\leq j\leq n-1} 2^{wj}) \mod r$ to avoid computing 
correction point $[\sum_{0\leq j\leq n-1}2* 2^{wj}]P$. This works for both base_field_chip and general_ecc_chip.

The accumulation $acc_i$ is computed from the bottom up: 

$$
\begin{align}
acc_{n-1} & = Q_{n-1} \\ 
acc_{n-2} & = 2^w acc_{n-1} + Q_{n-2} \\ 
acc_i & = 2^w acc_{i+1} + Q_i \\
& = 2(2^{w-1} acc_{i+1}) + Q_i \text{ for } i = n-3,...,2
\end{align}
$$

The scalar in $acc_{n-1},\dots, acc_2$ increases monotonically, and $acc_{n-3}...acc_2$ can be computed using laddr_incomplete. 
The last two steps $acc_{1}, acc_0$ might overflow (when $\ell = 1$ and $w = 2$) 
and need to use auxiliary generator and addition with assertions to ensure the x-coordinates are not the same: 

$$
\begin{align}
acc_1 & = (2^{w} acc_2 + aux) + Q_1\\ 
acc_0 & = (2^w acc_1 + Q_0) - 2^w aux
\end{align}
$$

### mul_batch_1d_horizontal
This algorithm uses addtion with assertions in all steps and the auxiliary generator in the last two steps. It is only suitable for computing 
$e_1 P_1 + e_2 P_2 + \cdots + e_n P_n$, where $P_1, \dots, P_n$ are randomly chosen, 
i.e., their discrete logarithms are unknown. The algorithm is not suitable for computing things like $eP + sP$.
