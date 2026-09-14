/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ~ Licensed to the Apache Software Foundation (ASF) under one
 ~ or more contributor license agreements.  See the NOTICE file
 ~ distributed with this work for additional information
 ~ regarding copyright ownership.  The ASF licenses this file
 ~ to you under the Apache License, Version 2.0 (the
 ~ "License"); you may not use this file except in compliance
 ~ with the License.  You may obtain a copy of the License at
 ~
 ~   http://www.apache.org/licenses/LICENSE-2.0
 ~
 ~ Unless required by applicable law or agreed to in writing,
 ~ software distributed under the License is distributed on an
 ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 ~ KIND, either express or implied.  See the License for the
 ~ specific language governing permissions and limitations
 ~ under the License.
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
$(document).ready(function () {

    function populateBlocked(ui) {
        var tab = ui.tab || ui.newTab;
        if (tab.attr('id') === 'blocked-tab') {
            $.ajax(window.location + '/blocked.json', {
                success: function (data) {
                    if (data && data.hrefs) {
                        if (data.hrefs.length > 0) {
                            var tbody = $('#invalid-urls-rows');
                            tbody.empty();
                            for (var i = 0; i < data.hrefs.length; i++) {
                                var cssClass = (i % 2) === 0 ? 'even' : 'odd';
                                // the blocked hrefs are attacker-controlled: build the cells with
                                // text() (text nodes) instead of interpolating them into markup,
                                // so recorded payloads cannot execute in the console origin
                                tbody.append($('<tr></tr>')
                                        .addClass(cssClass + ' ui-state-default')
                                        .append($('<td></td>').text(data.hrefs[i].href))
                                        .append($('<td></td>').text(String(data.hrefs[i].times))));
                            }
                            var table = $('#invalid-urls');
                            table.trigger('update');
                            var sorting = [[1, 1]];
                            table.trigger('sorton', [sorting]);
                        }
                    }
                }
            });
        }
    }

    $('#invalid-urls').tablesorter();
    $('#xss-tabs').tabs({
        create: function (event, ui) {
            populateBlocked(ui);
        },
        activate: function (event, ui) {
            populateBlocked(ui);
        }
    });
});


