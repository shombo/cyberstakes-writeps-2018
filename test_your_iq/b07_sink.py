#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: B07 Sink
# Generated: Mon Dec  3 11:29:52 2018
##################################################

if __name__ == '__main__':
    import ctypes
    import sys
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print "Warning: failed to XInitThreads()"

from PyQt4 import Qt
from gnuradio import analog
from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import math
import pmt
import sys
from gnuradio import qtgui


class b07_sink(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "B07 Sink")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("B07 Sink")
        qtgui.util.check_set_qss()
        try:
            self.setWindowIcon(Qt.QIcon.fromTheme('gnuradio-grc'))
        except:
            pass
        self.top_scroll_layout = Qt.QVBoxLayout()
        self.setLayout(self.top_scroll_layout)
        self.top_scroll = Qt.QScrollArea()
        self.top_scroll.setFrameStyle(Qt.QFrame.NoFrame)
        self.top_scroll_layout.addWidget(self.top_scroll)
        self.top_scroll.setWidgetResizable(True)
        self.top_widget = Qt.QWidget()
        self.top_scroll.setWidget(self.top_widget)
        self.top_layout = Qt.QVBoxLayout(self.top_widget)
        self.top_grid_layout = Qt.QGridLayout()
        self.top_layout.addLayout(self.top_grid_layout)

        self.settings = Qt.QSettings("GNU Radio", "b07_sink")
        self.restoreGeometry(self.settings.value("geometry").toByteArray())


        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 1000000
        self.deci = deci = 5
        self.baud = baud = 9600

        ##################################################
        # Blocks
        ##################################################
        self.low_pass_filter_0 = filter.fir_filter_ccf(1, firdes.low_pass(
        	1, samp_rate, 100000, 1000, firdes.WIN_HAMMING, 6.76))
        self.digital_clock_recovery_mm_xx_0 = digital.clock_recovery_mm_ff(samp_rate/deci/baud, 0.25*0.175*0.175, 0.5, 0.175, 0.005)
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, samp_rate,True)
        self.blocks_moving_average_xx_0 = blocks.moving_average_ff(int(samp_rate/deci/baud), 1/(1.0*samp_rate/deci/baud), 4000, 1)
        self.blocks_float_to_char_0 = blocks.float_to_char(1, 1)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, '/Users/shombo/Desktop/ctfs/cyberstakes/is_that_a_warble_in_your_voice/67_capture_new.32iq', False)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, '/Users/shombo/Desktop/ctfs/cyberstakes/is_that_a_warble_in_your_voice/test2', False)
        self.blocks_file_sink_0.set_unbuffered(False)
        self.analog_quadrature_demod_cf_0 = analog.quadrature_demod_cf(1)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_quadrature_demod_cf_0, 0), (self.blocks_moving_average_xx_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_float_to_char_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_moving_average_xx_0, 0), (self.digital_clock_recovery_mm_xx_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.digital_clock_recovery_mm_xx_0, 0), (self.blocks_float_to_char_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.analog_quadrature_demod_cf_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "b07_sink")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.samp_rate, 100000, 1000, firdes.WIN_HAMMING, 6.76))
        self.digital_clock_recovery_mm_xx_0.set_omega(self.samp_rate/self.deci/self.baud)
        self.blocks_throttle_0.set_sample_rate(self.samp_rate)
        self.blocks_moving_average_xx_0.set_length_and_scale(int(self.samp_rate/self.deci/self.baud), 1/(1.0*self.samp_rate/self.deci/self.baud))

    def get_deci(self):
        return self.deci

    def set_deci(self, deci):
        self.deci = deci
        self.digital_clock_recovery_mm_xx_0.set_omega(self.samp_rate/self.deci/self.baud)
        self.blocks_moving_average_xx_0.set_length_and_scale(int(self.samp_rate/self.deci/self.baud), 1/(1.0*self.samp_rate/self.deci/self.baud))

    def get_baud(self):
        return self.baud

    def set_baud(self, baud):
        self.baud = baud
        self.digital_clock_recovery_mm_xx_0.set_omega(self.samp_rate/self.deci/self.baud)
        self.blocks_moving_average_xx_0.set_length_and_scale(int(self.samp_rate/self.deci/self.baud), 1/(1.0*self.samp_rate/self.deci/self.baud))


def main(top_block_cls=b07_sink, options=None):

    from distutils.version import StrictVersion
    if StrictVersion(Qt.qVersion()) >= StrictVersion("4.5.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls()
    tb.start()
    tb.show()

    def quitting():
        tb.stop()
        tb.wait()
    qapp.connect(qapp, Qt.SIGNAL("aboutToQuit()"), quitting)
    qapp.exec_()


if __name__ == '__main__':
    main()
