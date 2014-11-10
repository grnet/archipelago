import sys, os


cur_dir = os.path.dirname(os.path.abspath(__file__))

project = u'archipelago'
copyright = u'2012-2013, GRNET'
version = open(os.path.join(cur_dir + '/../', 'version')).read().strip()
release = version
html_title = 'archipelago ' + version

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'
exclude_patterns = ['_build']
pygments_style = 'sphinx'
html_theme = 'default'
html_theme_options = {
	'collapsiblesidebar': 'true',
	'footerbgcolor':    '#55b577',
	'footertextcolor':  '#000000',
	'sidebarbgcolor':   '#ffffff',
	'sidebarbtncolor':  '#f2f2f2',
	'sidebartextcolor': '#000000',
	'sidebarlinkcolor': '#328e4a',
	'relbarbgcolor':    '#55b577',
	'relbartextcolor':  '#ffffff',
	'relbarlinkcolor':  '#ffffff',
	'bgcolor':          '#ffffff',
	'textcolor':        '#000000',
	'headbgcolor':      '#ffffff',
	'headtextcolor':    '#000000',
	'headlinkcolor':    '#c60f0f',
	'linkcolor':        '#328e4a',
	'visitedlinkcolor': '#63409b',
	'codebgcolor':      '#eeffcc',
	'codetextcolor':    '#333333',
}

#html_static_path = ['_static']
htmlhelp_basename = 'archipelagodoc'

ARCHIPELAGO_DOCS_BASE_URL = 'http://www.synnefo.org/docs'
extensions = ['sphinx.ext.autodoc',
              'sphinx.ext.intersphinx',
              'sphinx.ext.todo',
              'sphinx.ext.viewcode']
