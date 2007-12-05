//
// Copyright (c) 2007 Niels Provos <provos@citi.umich.edu>
// All rights reserved.
//
var _timeout = null;

function locationWithoutFragment() {
	var uri = top.location;
	return uri.toString().split('#')[0];
}

function gotResult(req) {
	if (req.status != 200) {
		error_box(locationWithoutFragment());
		return;
	}

	var response = req.responseXML;
	var danger = response.getElementsByTagName('danger')[0].firstChild.data;
	var complete = response.getElementsByTagName('complete')[0].firstChild.data;

	// we only notify the user of dangerous crap
	if (danger == 'dangerous') {
		danger_box(locationWithoutFragment());
	} else if (complete == 'complete') {
		results_box(locationWithoutFragment());
	} else if (!complete || !danger) {
		error_box(locationWithoutFragment());
	}
}

function launchCallback() {
	var req = new XMLHttpRequest();
	req.open('POST', '/_spybye_control_callback', true);
	req.onreadystatechange = function() {
		if (req.readyState == 4) {
			// Your callback code goes here
			gotResult(req);
		}
	}
	req.setRequestHeader('Content-Type',
	    'application/x-www-form-urlencoded');
	req.send('site=' + locationWithoutFragment());
}

function changeBox(uri, message, color, backgroundColor) {
	var el = document.getElementById('spybye_box');
	if (!el)
		return null;

	spybye_url = "http://spybye/?url=" + escape(uri) + "&noiframe=1";

	// if the timeout is still pending then remove it
	if (_timeout) {
		clearTimeout(_timeout);
		_timeout = null;
	}

	var inner_html = ("<a href='http://spybye/'>o</a> " + message +
	    "<a style='color:'" + color +"' href='" + spybye_url + "' " +
	    "target='_blank' " +
	    "onclick=\"window.open('" + spybye_url + "', 'SpyBye Result', 'width=500,height=600,resizable=1,scrollbars=1'); " +
	    "return false\">" + uri + "</a>" +
	    "<span align=right style='position:absolute; right:20px; text-weight:bold;'>" +
	    "<a href='#' onclick='hideBox(); return false'>x</a></span>");

	el.style.display = 'block';
	el.style.backgroundColor = backgroundColor;
	el.style.color = color;
	el.innerHTML = inner_html;

	return el
}

function results_box(uri) {
	changeBox(uri, "SpyBye has completed its analysis for ",
	    '#eeeeee', '#44aa33');
}

function danger_box(uri) {
	changeBox(uri, "Spybye has detected dangerous links on ",
	    '#112222', '#dd7766');
}

function error_box(uri) {
	changeBox(uri, "Spybye encountered an error analyzing ",
	    '#112222', '#dd7766');
}

function hideBox() {
	var el = document.getElementById('spybye_box');
	if (!el)
		return;

	el.style.display = 'none';
}

function take_control() {
	document.write("<div id=spybye_box style='color:#eeeeee;font-size:14px;position:absolute; left:0px; top:0px; width:100%; background-color:#44aa33;clear:both;z-index:2147483647;font-family:arial,sans-serif;padding:4px;text-align:left;'>SpyBye running normally ... <span align=right style='position:absolute; right:20px; text-weight:bold;'><a href='#' onclick='hideBox(); return false'>x</a></span></div>");

	_lambda = function() {
		_timeout = null;
		hideBox();
	}
	_timeout = setTimeout(_lambda, 2000);

	launchCallback();
}

if (top.location == self.location)
	take_control();
