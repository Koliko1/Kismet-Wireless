/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * DEBUG: Log file handling
 * AUTHOR: CSSI (Fabrice Agagah)
 */

#ifndef __PRELUDETRACKER_H__
#define __PRELUDETRACKER_H__

#include "globalregistry.h"
#include "messagebus.h"
#include "netracker.h"

#include <libprelude/prelude.hxx>

#define ANALYZER_MODEL "Kismet"
#define ANALYZER_CLASS "Wireless Monitor"
#define ANALYZER_MANUFACTURER "https://www.kismetwireless.net/"
#define VERSION "2016-01-R1"

using namespace Prelude;

class Preludetracker {
public:

	Preludetracker(GlobalRegistry *in_globalreg);
	~Preludetracker();

	// Raise an alert ...
	int RaiseHeavyAlert(int in_ref, kis_packet *in_pack, mac_addr bssid, mac_addr source,
	mac_addr dest, mac_addr other, int in_channel, string in_text);

	// Initialize Prelude Client
	void PreludeInitClient(const char *analyzer_name);

	// Alert when a new Network is detected
	int RaiseDetectNetwork(string type, string network, Netracker::tracked_network *net, kis_ieee80211_packinfo *packinfo);

	// Alert on crypto change
	int RaiseCryptAlert(string bssid, string network);

protected:

	GlobalRegistry *globalreg;
	ClientEasy *client;
};
#endif
