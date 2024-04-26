# RCPU (Remaining CPU)

This repository contains the implementation of the RCPU method, a method to estimate the remaining CPU of a node with SMT-enabled processors.

> Due to the commercial restrictions, we could not provide the evaluation dataset in the data center.
> The repository contains 
> 1. A standalone RCPU collector that collects the remaining CPU of a node.
> 2. A reference implementation of a Kubernetes plugin that uses the RCPU to do load-aware scheduling.
> 3. The evaluation scripts and the dataset for the SPEC Powerssj_2008 benchmark.

## Repository structure

```
   rcpu
   |- collector # A standalone RCPU collector
   |- plugins   # A reference implementation of a Kubernetes plugin
   |- ssj       # Evaluation scripts and dataset for the SPEC Powerssj_2008 benchmark
```

## RCPU Collector

The RCPU collector is a standalone tool that collects the remaining CPU of a node. The collector is written in Go.

![RCPU Collector](
    ./collector/rcpu.gif
)

The above image shows the collector running on a Intel Ice Lake server.
The collector displays 6 columns:
* `Time`: The time when the data was collected.
* `Avg CPU Usage`: The average CPU usage of the node, following common monitoring tools like top, htop, btop and bottom.
* `Adjusted CPU Usage`: The CPU usage adjusted with RCPU.
* `Avg Remaining CPU`: The average remaining CPU of the node, follwing the formula `100% - Avg CPU Usage`.
* `RCPU`: Our method, following the formula `100% - Adjusted CPU Usage`.
* `Difference`. The difference between `Avg Remaining CPU` and `RCPU`, following the formula `Avg Remaining CPU - RCPU`.

## RCPU Plugin

The RCPU plugin is a template implementation of a Kubernetes plugin that uses the RCPU to do load-aware scheduling.

Due to the commercial restrictions and the differences between the official and internal versions of Kubernetes, we cannot provide the detailed implementation of the plugin.
However, we provide a reference implementation that can be used as a starting point for reproduction and further development.

Like other metrics used to guide scheduling, the RCPU metrics can be obtained from Prometheus and be annotated to the node.
Then the plugin can then use the RCPU metrics to make scheduling decisions.

Another approach is modifying the kubelet, and report RCPU metrics directly into the `NodeStatus` object.
The approach could be a better choice for the users who have already maintained a fork of the Kubernetes codebase.

## SPEC Powerssj_2008

```
   ssj
   |- icx.parquet       # Dataset collected on the Intel Ice Lake Server
   |- clx.parquet       # Dataset collected on the Intel Cascade Lake Server
   |- ssj.icx.json      # SPEC powerssj_2008 data collected on the Intel Ice Lake Server
   |- ssj.clx.json      # SPEC powerssj_2008 data collected on the Intel Cascade Lake Server
   |- errors.parquet    # Error metrics
   |- speed.parquet     # Relative Time metrics
   |- eval.ipynb        # Jupyter Notebook for reproducing the results
```