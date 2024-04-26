package rcpu

import (
	"context"
	"fmt"
	"strconv"

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

var _ framework.FilterPlugin = &RCPUScheduler{}
var _ framework.ScorePlugin = &RCPUScheduler{}

const (
	Name = "RCPUScheduler"

	DefaultRCPUThreshold = int64(0.4 * 1000) // Default threshold for banning a node based on rcpu utilization, we multiply by 1000 to convert it to millicores to avoid floating point arithmetic
	RCPUMaxScore = int64(1.0 * 1000)

	RCPUFeatureGateKey = "rcpu-scheduler/enable"
	RCPUMetric1mKey    = "rcpu-scheduler/rcpu_1min"
	RCPUMetric5mKey    = "rcpu-scheduler/rcpu_5min"
	RCPUMetric15mKey   = "rcpu-scheduler/rcpu_15min"

	DefaultRCPUMetric = RCPUMetric15mKey
)

type RCPUScheduler struct {
	handle framework.Handle
}

func (rs *RCPUScheduler) Name() string {
	return Name
}

func IsDaemonSetPod(pod *v1.Pod) bool {
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "DaemonSet" {
			return true
		}
	}
	return false
}

func isOverloaded(annotations map[string]string, metric string, threshold int64) bool {
	rcpuStr, ok := annotations[metric]
	if !ok {
		return false
	}

	rcpu, err := strconv.ParseInt(rcpuStr, 10, 64)
	if err != nil {
		return false
	}

	return rcpu >= threshold
}

func (rs *RCPUScheduler) Filter(ctx context.Context, cycleState *framework.CycleState, pod *v1.Pod, nodeInfo *framework.NodeInfo) *framework.Status {
	if IsDaemonSetPod(pod) {
		return framework.NewStatus(framework.Success, "")
	}

	node := nodeInfo.Node()
	if node == nil {
		return framework.NewStatus(framework.Error, "node not found")
	}

	nodeAnnotations := node.GetAnnotations()
	if nodeAnnotations == nil {
		return framework.NewStatus(framework.Success, "")
	}

	annotation, ok := nodeAnnotations[RCPUFeatureGateKey]
	if !ok || annotation != "true" {
		return framework.NewStatus(framework.Success, "")
	}

	if isOverloaded(nodeAnnotations, DefaultRCPUMetric, DefaultRCPUThreshold) {
		return framework.NewStatus(framework.Unschedulable, "rcpu utilization is too high")
	}

	return framework.NewStatus(framework.Success, "")
}

func getNodeScore(annotations map[string]string, metric string) (int64, bool) {
	rcpuStr, ok := annotations[metric]
	if !ok {
		return 0, false
	}

	rcpu, err := strconv.ParseInt(rcpuStr, 10, 64)
	if err != nil {
		return 0, false
	}

	return max(0, RCPUMaxScore - rcpu), true
}

func (rs *RCPUScheduler) Score(ctx context.Context, state *framework.CycleState, pod *v1.Pod, nodeName string) (int64, *framework.Status) {
	nodeInfo, err := rs.handle.SnapshotSharedLister().NodeInfos().Get(nodeName)
	if err != nil {
		return 0, framework.NewStatus(framework.Error, fmt.Sprintf("getting node %q from Snapshot: %v", nodeName, err))
	}

	node := nodeInfo.Node()
	if node == nil {
		return 0, framework.NewStatus(framework.Error, "node not found")
	}

	nodeAnnotations := node.Annotations
	if nodeAnnotations == nil {
		return 0, framework.NewStatus(framework.Success, "")
	}

	annotation, ok := nodeAnnotations[RCPUFeatureGateKey]
	if !ok || annotation != "true" {
		return 0, framework.NewStatus(framework.Success, "")
	}

	score, ok := getNodeScore(nodeAnnotations, DefaultRCPUMetric)
	if !ok {
		return 0, framework.NewStatus(framework.Error, "failed to get node score")
	}

	return score, framework.NewStatus(framework.Success, "")
}

func (rs *RCPUScheduler) ScoreExtensions() framework.ScoreExtensions {
	// We don't need to implement normalizer, since the score is already normalized
	return nil
}
