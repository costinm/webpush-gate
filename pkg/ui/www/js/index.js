"use strict";

function wifiHandler() {
    $("#do_sync").click(function () {
        fetch("debug/scan?s=1").then(function (res) {
            return res.json();
        }).then(function (json) {
            // TODO: update just the wifi table. Reload also refreshes,
            // since visibledevices is returned.
            //location.reload();
        });
    });

    $("#apcheck").change(function () {
        if ($("#apcheck")[0].checked) {
            fetch("dmesh/uds?q=/wifi/p2p&ap=1").then(function (json) {
                //    location.reload();
            });
        } else {
            fetch("dmesh/uds?q=/wifi/p2p&ap=0").then(function (json) {
                //    location.reload();
            });
        }
    });
    $("#autocon").click(function () {
        fetch("wifi/con").then(function (json) {
            location.reload();
        });
    });
    $("#mc").click(function () {
        fetch("dmesh/mc").then(function (json) {
            location.reload();
        });
    });
    $("#nanping").click(function () {
        fetch("dmesh/uds?q=/wifi/nan/ping").then(function (json) {
            location.reload();
        });
    });
    $("#nanoff").click(function () {
        fetch("dmesh/uds?q=/wifi/nan/stop").then(function (json) {
            location.reload();
        });
    });
    $("#nanon").click(function () {
        fetch("dmesh/uds?q=/wifi/nan/start").then(function (json) {
            location.reload();
        });
    });

    fetch("dmesh/ll/if").then(function (res) {
        return res.json();
    }).then(function (json) {
    })

    eventsHandler()

}

function eventsHandler() {
    //$("#do_sync").click(function () {
    //updateEV()
    //});

    updateEV();

    var evtSource = new EventSource("debug/eventss");
    evtSource.onmessage = function (e) {
        console.log("XXX EVENT", e)
        onEvent(JSON.parse(e.data))
    }
    evtSource.onerror = function (e) {
        console.log("event err", e)
    }
    evtSource.onopen = function (e) {
        console.log("event open", e)
    }
    //evtSource.addEventListener("wifi/scan", onEvent)
}

function updateTCP() {
    fetch("/dmesh/tcp").then(function (res) {
        if (console != null) {
            console.log(res);
        }
        return res.json();
    }).then(function (json) {
        $("#tcptable tbody").remove();
        let t = $("#tcptable").get()[0]

        $.each(json, function (i, ip) {
            let row = t.insertRow(-1);

            let cell = $("<td />");
            cell.html("<div>" + i + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.Count + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.SentBytes + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.RcvdBytes + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.Last + "</div>");
            $(row).append(cell);

            //cell.title = JSON.stringify(ip);
            //cell.tooltip();
            $(row).append(cell);


        });
    });
}


function updateUDP() {
    fetch("/dmesh/udp").then(function (res) {
        if (console != null) {
            console.log(res);
        }
        return res.json();
    }).then(function (json) {
        $("#tcptable tbody").remove();
        let t = $("#udptable").get()[0]

        $.each(json, function (i, ip) {
            let row = t.insertRow(-1);

            let cell = $("<td />");
            cell.html("<div>" + i + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.Count + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.SentBytes + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.RcvdBytes + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.Last + "</div>");
            $(row).append(cell);

            //cell.title = JSON.stringify(ip);
            //cell.tooltip();
            $(row).append(cell);
        });
    });
}


function onEvent(ev) {
    if (ev.to == undefined) {
        return
    }
    let row = "<tr>";

    row += "<td>" + ev.to +
        "<br>" + ev.from +
        "</br>" + ev.time +
        "</td>";

    row += "<td>";

    $.each(ev.meta, function (k, v) {
        if (false && ev.to.startsWith("/SYNC") && k == "Node") {
            let vv = JSON.parse(v)

            row += " NodeUA = " + vv.Reg.UA + "</br>";
            row += " NodeVIP = " + vv.vip + "</br>";

            row += " NodeGW = " + JSON.stringify(vv.gw) + "</br>";
            if (vv.Reg.nodes != undefined) {
                $.each(vv.Reg.nodes, function (k, v) {
                    row += " Node " + k + " = " + JSON.stringify(v) + "</br>";
                })
            }

            if (vv.Reg.wifi != undefined) {
                row += " Wifi = " + JSON.stringify(vv.Reg.wifi) + "</br>";
                // $.each(vv.Reg.wifi.P2P, function (k, v) {
                //     row += " Wifi " + k + " = " + v.Build + " " + v.Name + " " + v.Net + " " + v.SSID + " " + v.Pass + "</br>";
                // })
            }

        } else {
            row += k + " = " + v + "</br>";
        }

    })
    if (ev.path) {
        row += "<br/>" + ev.path;
    }
    row += "</td>";
    row += "</tr>";

    // $.each(ip.Value.Meta, function (k, v) {
    //     txt += k + "= <pre class='prettyprint'><code>"  + v + "</code></pre>";
    // })

    $(row).prependTo('#evtable tbody');

}

function updateEV() {
    fetch("debug/eventslog").then(function (res) {
        if (console != null) {
        }
        return res.json();
    }).then(function (json) {
        $("#evptable tbody").remove();
        //let t = $("#evtable").get()[0]

        console.log("events1", json)
        if (json) {
            $.each(json, function (i, ip) {
                onEvent(ip);

            });
        }
    });
}


// window.addEventListener("message", function (e) {
//     console.log("Main onmessage " + e);
//     if (e.data.log) {
//         console.log(e.data.log);
//     } else {
//
//     }
// }, false);

$('#svc').click(function (event) {
    // Remember the link href
    let href = this.href;

    // Don't follow the link
    event.preventDefault();

    fetch(href).then(function (res) {
        console.log(res.json());
    });
});

function updateIP6() {
    // fetch("/dmesh/ip6").then(function (res) {
    //     console.log(res);
    //     return res.json();
    // }).then(function (json) {
    //     $("#ip6table tr").remove();
    //     let t = $("#ip6table").get()[0]
    //
    //     $.each(json, function (i, ip) {
    //         let row = t.insertRow(-1);
    //         let cell = $("<td />");
    //         cell.html("<div>" + ip.UserAgent + "</div>");
    //         $(row).append(cell);
    //
    //         cell = $("<td />");
    //         cell.html("<div>" + ip.GW.IP + "</div>");
    //         $(row).append(cell);
    //
    //         cell = $("<td/>");
    //         cell.html("<div  data-toggle='tooltip'>" + ip.LastSeen + "</div>");
    //         cell.title = JSON.stringify(ip);
    //         cell.tooltip();
    //         $(row).append(cell);
    //     });
    // });

    /*
    fetch("/dmesh/tcp").then(function (res) {
        console.log(res);
        return res.json();
    }).then(function (json) {
        $("#tcptable tr").remove();
        let t = $("#ip6table").get()[0]

        $.each(json, function (i, ip) {
            let row = t.insertRow(-1);
            let cell = $("<td />");

            cell.html("<div>" + i + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.Count + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.SentBytes + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.RcvdBytes + "</div>");
            $(row).append(cell);

            cell = $("<td />");
            cell.html("<div>" + ip.Last + "</div>");
            $(row).append(cell);


            cell.title = JSON.stringify(ip);
            //cell.tooltip();
            $(row).append(cell);
        });
    });
    */

}

// $(document).ready(function () {
//     $("#do_sync").click(function () {
//         console.log("Sync")
//         fetch("/dmesh/rd").then(function (res) {
//             updateIP6()
//         })
//     });
//
//     updateIP6();
// })

