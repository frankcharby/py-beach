###############################################################################
#   REQUIREMENTS:
#   build-essentials
#   python-dev
#   python-setuptools
#   apt-get install build-essentials python-dev python-setuptools
###############################################################################

from setuptools import setup, Command
import glob
import os
import beach

class PyTest( Command ):
    user_options = []
    def initialize_options( self ):
        pass

    def finalize_options( self ):
        pass

    def run( self ):
        import subprocess
        import sys
        errno = subprocess.call( [ sys.executable, 'runtests.py', '-v', 'tests/' ] )
        raise SystemExit( errno )

dashDir = 'beach/dashboard/'
dashboardFiles = []
for root, dirnames, filenames in os.walk( dashDir ):
    for f in filenames:
        dashboardFiles.append( os.path.join( root, f ).replace( dashDir, '' ) )

setup( name = 'beach',
       version = beach.__version__,
       description = 'Simple private python cloud framework',
       url = 'http://www.refractionpoint.com/beach.html',
       author = 'refractionPOINT',
       author_email = 'maxime@refractionpoint.com',
       license = 'GPLv2',
       packages = [ 'beach', 'beach.dashboard' ],
       #data_files = dashboardFiles,
       package_data = { 'beach.dashboard' : dashboardFiles },
       zip_safe = False,
       cmdclass = {'test': PyTest},
       install_requires = [ 'gevent',
                            'pyzmq',
                            'netifaces',
                            'pyyaml',
                            'psutil',
                            'web.py',#'prefixtree',
                            'msgpack-python',],#'M2crypto'],
       long_description = 'Python private compute cloud framework with a focus on ease of deployment and expansion rather than pure performance.' )
