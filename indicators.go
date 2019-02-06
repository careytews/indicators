package indicators

import (
	"strings"

	log "github.com/sirupsen/logrus"
	dt "github.com/trustnetworks/analytics-common/datatypes"
)

// Implementation Notes and Terminology:
//	- 'truth' means the outcome (true/false) of a boolean operation (OR|AND|NOT)
//	- truth might be unknown (due to operands being unknown)
//	- 'resolved' means the truth is known
//	- a 'node' is a node in a boolean tree
//	- if a node has children, it must have a boolean operator (OR|AND|NOT)
//	- if a node as NO children (a leaf-node) it will have a 'pattern'
//	- a 'pattern' is something to match on
//	- a node may have an 'Indicator' which is spat out if the node is 'true'
//	- 'children' are specified in the IOC JSON definition file(s), but 'parents'
//      are constructed at IOC definition load time
//	- a node in the JSON definitions may simply be a reference (Ref) to
//		another node.
//	- nodes only need an ID if they are being referenced

type truth int

// A tri-state boolean. The 'truth' of a boolean operator is unknown until
// details of the state of its children (its operands) are known.
const (
	truthUnknown truth = iota
	truthTrue
	truthFalse
)

// IndicatorDefinitions defines the file format of IOC definitions.
// IOCs could be defined with multiple of such files.
type IndicatorDefinitions struct {
	Description string           `json:"description,omitempty"`
	Version     string           `json:"version,omitempty"`
	Definitions []*IndicatorNode `json:"definitions,omitempty"`
}

// IndicatorNode is a node in a boolean tree.
// A node may have children, in which case it must have an Operator, or
//  it might be a leaf node, in which case it must have a Pattern to match on.
// A node may be just a reference to another 'concrete' node - you cannot
//  reference a reference node though (there is no point)
// Children are specified in the IOCs definition file(s); links to Parents are
//  created at IOC def load time.
// This struct is used for both the IOC def file(s) and the runtime lookups.
type IndicatorNode struct {
	ID          string           `json:"id,omitempty"`
	Comment     string           `json:"comment,omitempty"`
	Ref         string           `json:"ref,omitempty"`
	Operator    string           `json:"operator,omitempty"` // OR|AND|NOT
	Indicator   *dt.Indicator    `json:"indicator,omitempty"`
	Parents     []*IndicatorNode `json:"parents,omitempty"`
	Children    []*IndicatorNode `json:"children,omitempty"`
	SiblingNots []int            `json:"siblingnots,omitempty"`
	Pattern     *Pattern         `json:"pattern,omitempty"`

	// Runtime state:
	truth   truth // the 'truth' of this node, maybe unknown
	eventID int   // the event ID currently being processed
	UseOriginalIndicatorValue bool // decide whether to fetch the indicator value from children
}

// Pattern is the pattern to match on
// The Type is the type of event property to match, e.g. "country"
// Value is the value to match
// Value2 is a second value to match, e.g. required for a range match
// Match is the type of match to perform:
//    - string (string match of Value, the default if Match is not specified)
//    - int (an integer match of Value)
//    - range (an integer range match of Value-Value2 inclusive)
//    - dns (a DNS hostname match of Value)
type Pattern struct {
	Type   string `json:"type,omitempty"`
	Value  string `json:"value,omitempty"`
	Value2 string `json:"value2,omitempty"`
	Match  string `json:"match,omitempty"`
}

var trueNode = IndicatorNode{truth: truthTrue}
var falseNode = IndicatorNode{truth: truthFalse}

// Fire should be called when node becomes True, i.e. the node resolves to true
// because its condition is satisfied (e.g, due to pattern patch or boolean
// operator being true)
func (node *IndicatorNode) Fire(evID int) ([]*dt.Indicator, []int) {
	return node.setTruth(&trueNode, evID)
}

// ResolveNot should be called to resolve the truth of NOT nodes, given
// the knowledge that its child can now be assumed truthFalse.
func (node *IndicatorNode) ResolveNot(evID int) ([]*dt.Indicator, []int) {
	return node.setTruth(&falseNode, evID)
}

//// Private methods ////

// setTruth attempts to set the truth of the node, according to the state of
// the child node being passed in. E.g. if this node is an OR and the child
// is true, then this node becomes true. The result may be that the state of
// this node is still undertermined (truthUnknown).
//
// The latest true child node's indicator values are propagated up the chain.
//
// Beware: this function uses recursion
//

func (node *IndicatorNode) setTruth(childNode *IndicatorNode, evID int) ([]*dt.Indicator, []int) {
	var indicators []*dt.Indicator
	var discoveredNots []int

	discoveredNots = append(discoveredNots, node.SiblingNots...)

	if childNode.truth == truthUnknown {
		return nil, nil // should not call this function with unknown truth
	}

	// If the node's event ID does not match, it's state is old. Reset it.
	if node.eventID != evID {
		node.truth = truthUnknown
		node.eventID = evID // remember what the current event is
		if node.Operator != "" {
			node.Pattern = nil
		}
	}

	// Default is to not set this node to true or false
	setNodeTo := truthUnknown

	// If truth of this node already known then nothing to do
	if node.truth == truthUnknown {
		if node.Operator != "" {
			switch node.Operator {

			case "OR":
				if childNode.truth == truthTrue {
					setNodeTo = truthTrue
					if node.Pattern == nil {
						node.Pattern = childNode.Pattern
					}
				}

			case "AND":
				if childNode.truth == truthFalse {
					setNodeTo = truthFalse
				} else {
					// See if all the children are now true
					setNodeTo = truthTrue
					for _, child := range node.Children {
						if child.eventID != node.eventID || child.truth != truthTrue {
							setNodeTo = truthUnknown
							break
						}
					}

					if setNodeTo == truthTrue && node.Pattern == nil {
						node.Pattern = node.Children[0].Pattern
					}
				}

			case "NOT":
				if childNode.truth == truthTrue {
					setNodeTo = truthFalse
				} else {
					setNodeTo = truthTrue
				}

			default:
				log.Warnf("Unrecognised operator '%s'", node.Operator)
			}
		} else {
			setNodeTo = childNode.truth // this is a leaf node
		}

		// Are we setting this node's truth?
		if setNodeTo != truthUnknown {

			node.truth = setNodeTo // set the truth of this node

			// If true, see if any Indicators to return
			if node.truth == truthTrue && node.Indicator != nil {
				if node.Pattern != nil {
					if !node.UseOriginalIndicatorValue {
						parts := strings.Split(node.Pattern.Type, ".")
						items := len(parts)

						// The match type is in the pattern to start with, and the "src" or "dest"
						// prefix has to be removed before copying the values into the indicator
						if items > 2 {
							log.Warnf("Indicator % type has % parts. Expected 1 or 2.", node.Indicator.Id, items)
						}

						if len(parts) > 1 {
							node.Indicator.Type = parts[1]
						} else {
							node.Indicator.Type = parts[0]
						}
						node.Indicator.Value = node.Pattern.Value
					}
				} else {
					log.Warnf("Indicator % no pattern", node.Indicator.Id)
				}
				indicators = append(indicators, node.Indicator)
			}

			// Check any parents to see if they are now satisfied
			for _, parent := range node.Parents {
				inds, discNots := parent.setTruth(node, evID)
				if inds != nil {
					// Record that these Indicators happened
					indicators = append(indicators, inds...)
				}
				if discNots != nil {
					discoveredNots = append(discoveredNots, discNots...)
				}
			}
		}
	}
	return indicators, discoveredNots
}
