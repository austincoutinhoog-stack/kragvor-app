package com.kragvor.app;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;
import com.kragvor.signal.SignalDetectorPlugin;

public class MainActivity extends BridgeActivity {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		registerPlugin(SignalDetectorPlugin.class);
		super.onCreate(savedInstanceState);
	}
}
