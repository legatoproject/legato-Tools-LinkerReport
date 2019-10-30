// Dimensions of sunburst.
var sun_width = 1000;
var sun_height = 800;
var sun_radius = Math.min(sun_width, sun_height) / 2;

// Breadcrumb dimensions: width, height, spacing, width of tip/tail.
var b = {
  w: 100, h: 30, s: 3, t: 10
};

var ram_colour  = "#5499C7";
var rom_colour  = "#7D3C98";
var both_colour = "#16A085";
var root_colour = "#BDC3C7";

// Mapping of step names to colors.
var colors = {
  ".bss":               ram_colour,
  ".heap":              ram_colour,
  ".sbss":              ram_colour,
  ".stack_dummy":       ram_colour,

  ".exception_vector":  both_colour,
  ".ram_text":          both_colour,
  ".uncached":          both_colour,

  ".data":              both_colour,
  ".sdata":             both_colour,

  ".rodata":            rom_colour,
  ".rodatafiller":      rom_colour,
  ".text":              rom_colour,

  "<root>":             root_colour
};

var x = d3.scale.linear()
    .range([0, 2 * Math.PI]);

var y = d3.scale.sqrt()
    .range([0, sun_radius]);

// Total size of all segments; we set this later, after loading the data.
var totalSize = 0;
var topLevel = {};

// Sunburst chart
var vis = d3.select("#chart").append("svg:svg")
    .attr("width", sun_width)
    .attr("height", sun_height)
    .append("svg:g")
    .attr("id", "container")
    .attr("transform", "translate(" + sun_width / 2 + "," + sun_height / 2 + ")");

var partition = d3.layout.partition()
    .value(function(d) { return d.size; });

var arc = d3.svg.arc()
    .startAngle(function(d) { return Math.max(0, Math.min(2 * Math.PI, x(d.x))); })
    .endAngle(function(d) { return Math.max(0, Math.min(2 * Math.PI, x(d.x + d.dx))); })
    .innerRadius(function(d) { return Math.max(0, y(d.y)); })
    .outerRadius(function(d) { return Math.max(0, y(d.y + d.dy)); });

function renderSunburst(json) {
  // Basic setup of page elements.
  initializeBreadcrumbTrail();
  drawLegend();

  // Bounding circle underneath the sunburst, to make it easier to detect
  // when the mouse leaves the parent g.
  vis.append("svg:circle")
      .attr("r", sun_radius)
      .style("opacity", 0);

  // For efficiency, filter nodes to keep only those large enough to see.
  var nodes = partition.nodes(json)
      .filter(function(d) {
      return (Math.max(0, Math.min(2 * Math.PI, x(d.x + d.dx))) > 0.005); // 0.005 radians = 0.29 degrees
      });

  var path = vis.data([json]).selectAll("path")
      .data(nodes)
      .enter().append("svg:path")
      .attr("d", arc)
      .attr("fill-rule", "evenodd")
      .style("fill", function(d) {
          return colors[d.section];
       })
      .style("opacity", 1)
      .on("mouseover", mouseover)
      .on("click", click);

  // Add the mouseleave handler to the bounding circle.
  d3.select("#container").on("mouseleave", mouseleave);

  // Get total size of the tree = value of root node from partition.
  rootNode = path.node().__data__;
  totalSize = rootNode.value;
  topLevel = rootNode;

  setPercentage(topLevel.value, topLevel.name);

  updateBreadcrumbs([rootNode], "100%");
}

function renderSummary(json) {
  var table = d3.select('table#summary-table');
  table.select("td#rom").text(json['ROM']);
  table.select("td#ram").text(json['RAM']);
  table.selectAll("td.both").text(json['RAM+ROM']);
  table.select("td#totalram").text(json['RAM'] + json['RAM+ROM']);
  table.select("td#totalrom").text(json['ROM'] + json['RAM+ROM']);

  table = d3.select('div#summary-info tbody');
  var row = table.append("tr");
  row.append("td").text("Device").classed("property", true);
  row.append("td").text(json['Device']).classed("value", true);

  json['Build'].forEach(function(e) {
    var row = table.append("tr");
    row.append("td").text(e.name).classed("property", true);
    row.append("td").text(e.value).classed("value", true);
  })

  if (json['CSV'])
  {
    var csvfile = json['Device'] + ".csv";
    var datalink = d3.select('p#data-link');
    datalink.html(
      "Download symbol data in CSV format: <a href=\"" + csvfile + "\">" + csvfile + "</a>");
  }
}

function render() {
  var device = summary_map['Device'];
  colors[device] = colors['<root>'];
  delete colors['<root>'];

  var title = d3.select('title');
  title.text(device.toUpperCase() + " Binary Size Analysis");

  renderSunburst(size_map);
  renderSummary(summary_map);
}

function getPercentageString(val, tol) {
  var percentage = (100 * val / tol).toPrecision(3);
  var percentageString = percentage + "%";
  if (percentage < 0.1) {
    percentageString = "< 0.1%";
  }

  return percentageString;
}

// Fade all but the current sequence, and show it in the breadcrumb trail.
function mouseover(d) {
  setPercentage(d.value, d.name);

  var sequenceArray = getAncestors(d);
  var percentageStr = getPercentageString(d.value, totalSize);
  updateBreadcrumbs(sequenceArray, percentageStr);

  // Fade all the segments.
  d3.selectAll("path")
      .style("opacity", 0.3);

  // Then highlight only those that are an ancestor of the current segment.
  vis.selectAll("path")
      .filter(function(node) {
                return (sequenceArray.indexOf(node) >= 0);
              })
      .style("opacity", 1);
}

// Restore everything to full opacity when moving off the visualization.
function mouseleave(d) {

  // Hide the breadcrumb trail
  d3.select("#trail")
      .style("visibility", "hidden");

  // Deactivate all segments during transition.
  d3.selectAll("path").on("mouseover", null);

  // Transition each segment to full opacity and then reactivate it.
  d3.selectAll("path")
      .transition()
      .duration(1000)
      .style("opacity", 1)
      .each("end", function() {
              d3.select(this).on("mouseover", mouseover);
            });

  setPercentage(topLevel.value, topLevel.name);

  var sequenceArray = getAncestors(topLevel);
  var percentageStr = getPercentageString(topLevel.value, totalSize);
  updateBreadcrumbs(sequenceArray, percentageStr);
}

function setPercentage(size, name) {
  d3.select("#percentage")
      .text(size);

  d3.select("#percentage_desc")
      .text(name);

  d3.select("#explanation")
      .style("visibility", "");
}

function getRoot(node) {
  var current = node;
  while (current.parent) {
    current = current.parent;
  }
  return current;
}

// Given a node in a partition layout, return an array of all of its ancestor
// nodes, highest first, but excluding the root.
function getAncestors(node) {
  var path = [];
  var current = node;
  while (current.parent) {
    path.unshift(current);
    current = current.parent;
  }
  path.unshift(current);
  return path;
}

function initializeBreadcrumbTrail() {
  // Add the svg area.
  var trail = d3.select("#sequence").append("svg:svg")
      .attr("width", sun_width*2)
      .attr("height", 50)
      .attr("id", "trail");
  // Add the label at the end, for the percentage.
  trail.append("svg:text")
    .attr("id", "endlabel")
    .style("fill", "#000");
}

// Generate a string that describes the points of a breadcrumb polygon.
function breadcrumbPoints(d, i) {
  var points = [];
  points.push("0,0");
  points.push(b.w + ",0");
  points.push(b.w + b.t + "," + (b.h / 2));
  points.push(b.w + "," + b.h);
  points.push("0," + b.h);
  if (i > 0) { // Leftmost breadcrumb; don't include 6th vertex.
    points.push(b.t + "," + (b.h / 2));
  }
  return points.join(" ");
}

// Update the breadcrumb trail to show the current sequence and percentage.
function updateBreadcrumbs(nodeArray, percentageString) {

  // Data join; key function combines name and depth (= position in sequence).
  var g = d3.select("#trail")
      .selectAll("g")
      .data(nodeArray, function(d) { return d.name + d.depth; });

  // Add breadcrumb and label for entering nodes.
  var entering = g.enter().append("svg:g");

  entering.append("svg:polygon")
      .attr("points", breadcrumbPoints)
      .style("fill", function(d) {
          return colors[d.section];
       })
      .style("cursor", "pointer")
      .on("click", function(d) { click(d); mouseover(d); });

  entering.append("svg:text")
      .attr("x", (b.w + b.t) / 2)
      .attr("y", b.h / 2)
      .attr("dy", "0.35em")
      .attr("text-anchor", "middle")
      .text(function(d) { return d.name; })
      .style("cursor", "pointer")
      .on("click", function(d) { click(d); mouseover(d); });

  // Set position for entering and updating nodes.
  g.attr("transform", function(d, i) {
    return "translate(" + (i+0.2) * (b.w + b.s) + ", 0)";
  });

  // Remove exiting nodes.
  g.exit().remove();

  // Now move and update the percentage at the end.
  d3.select("#trail").select("#endlabel")
      .attr("x", (nodeArray.length + 0.5) * (b.w + b.s))
      .attr("y", b.h / 2)
      .attr("dy", "0.35em")
      .attr("text-anchor", "middle")
      .text(percentageString);

  // Make the breadcrumb trail visible, if it's hidden.
  d3.select("#trail")
      .style("visibility", "");

}

function drawLegend() {

  // Dimensions of legend item: width, height, spacing, radius of rounded rect.
  var li = {
    w: 100, h: 30, s: 3, r: 3
  };

  var legend = d3.select("#legend").append("svg:svg")
      .attr("width", li.w)
      .attr("height", d3.keys(colors).length * (li.h + li.s));

  var g = legend.selectAll("g")
      .data(d3.entries(colors))
      .enter().append("svg:g")
      .attr("transform", function(d, i) {
              return "translate(0," + i * (li.h + li.s) + ")";
           });

  g.append("svg:rect")
      .attr("rx", li.r)
      .attr("ry", li.r)
      .attr("width", li.w)
      .attr("height", li.h)
      .style("fill", function(d) { return d.value; });

  g.append("svg:text")
      .attr("x", li.w / 2)
      .attr("y", li.h / 2)
      .attr("dy", "0.35em")
      .attr("text-anchor", "middle")
      .text(function(d) { return d.key; });
}

function click(d) {
  vis.transition()
      .duration(750)
      .tween("scale", function() {
        var xd = d3.interpolate(x.domain(), [d.x, d.x + d.dx]),
            yd = d3.interpolate(y.domain(), [d.y, 1]),
            yr = d3.interpolate(y.range(), [d.y ? 20 : 0, sun_radius]);
        return function(t) { x.domain(xd(t)); y.domain(yd(t)).range(yr(t)); };
      })
    .selectAll("path")
      .attrTween("d", function(d) { return function() { return arc(d); }; });

  topLevel = d;
  setPercentage(topLevel.name, topLevel.value);
}

// Render the graphs
render();
