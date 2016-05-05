// Karma config for common-requirejs suite.
// Docs in common/static/common/js/karma.common.conf.js

/* jshint node: true */
/*jshint -W079 */

'use strict';
var path = require('path');
var configModule = require(path.join(__dirname, '../../common/static/common/js/karma.common.conf.js'));

var options = {

    includeCommonFiles: true,

    normalizePathsForCoverageFunc: function (appRoot, pattern) {
        return path.join(appRoot, '/common/static/' + pattern);
    },

    libraryFiles: [
        {pattern: 'coffee/src/**/*.js'},
        {pattern: 'js/libs/**/*.js'},
        {pattern: 'js/test/**/*.js'},
        {pattern: 'js/vendor/**/*.js'}
    ],

    sourceFiles: [],

    specFiles: [
        {pattern: 'common/js/spec/**/*spec.js'}
    ],

    fixtureFiles: [
        {pattern: 'common/templates/**/*.*'}
    ],

    runFiles: [
        {pattern: 'common/js/spec/main_requirejs.js', included: true}
    ]
};

module.exports = function (config) {
    configModule.configure(config, options);
};
