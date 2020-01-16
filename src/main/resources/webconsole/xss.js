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
                            var rows = '';
                            for (var i = 0; i < data.hrefs.length; i++) {
                                var cssClass = (i % 2) === 0 ? 'even' : 'odd';
                                rows += `<tr class="${cssClass} ui-state-default">
                                            <td>${data.hrefs[i].href}</td>
                                            <td>${data.hrefs[i].times}</td>
                                        </tr>`;
                            }
                            $('#invalid-urls-rows').html(rows);
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


