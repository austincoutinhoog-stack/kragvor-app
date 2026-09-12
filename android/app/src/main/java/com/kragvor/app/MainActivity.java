package com.kragvor.app;

import com.getcapacitor.BridgeActivity;
import com.kragvor.signal.SignalDetectorPlugin;

public class MainActivity extends BridgeActivity {
	@Override
	public void onCreate(android.os.Bundle savedInstanceState) {
		registerPlugin(SignalDetectorPlugin.class);
		super.onCreate(savedInstanceState);
	}
}
