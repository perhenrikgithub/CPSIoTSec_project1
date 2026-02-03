import sys
import time
from pymavlink import mavutil
import math
import numpy as np

# --- CONFIGURATION ---
# Connection string for SITL (standard UDP port)
CONNECTION_STR = 'udp:127.0.0.1:14550'
PARAM = 'SIM_GPS1_GLTCH_Y'  # Parameter to manipulate e.g 'SIM_GPS1_GLTCH_X' or 'SIM_GPS1_GLTCH_Y'

# --- CONNECT ---
print(f"--- Connecting to drone on {CONNECTION_STR} ---")
# source_system=255 means we are a GCS (Ground Control Station)
master = mavutil.mavlink_connection(CONNECTION_STR, source_system=255)

# Wait for the first heartbeat to confirm connection
print("Waiting for heartbeat...")
master.wait_heartbeat()
print(f"Heartbeat received from System {master.target_system}, Component {master.target_component}")

# --- HELPER FUNCTION ---
def meters_to_deg_lon(meters: float, latitude_deg: float = -35) -> float:
    """
    Convert east-west distance in meters to degrees of longitude
    at a given latitude using a spherical Earth approximation.
    
    Positive result = eastward
    Negative result = westward (if meters is negative)

    param: meters: Distance in meters
    param: latitude_deg: Latitude in degrees where the conversion is applied, default -35 (approx. ArduPilot SITL default)
    return: Degrees of longitude corresponding to the input distance in meters
    """
    METERS_PER_DEG_AT_EQUATOR = 111_320.0
    return meters / (METERS_PER_DEG_AT_EQUATOR * math.cos(math.radians(latitude_deg)))

def set_param(param_id, value):
    """
    Sends a MAVLink PARAM_SET message.
    param_id: String (e.g., 'SIM_GPS1_GLTCH_Y')
    value: Float value
    """
    master.mav.param_set_send(
        master.target_system,
        master.target_component,
        param_id.encode('utf-8'), # ArduPilot expects bytes
        value,
        mavutil.mavlink.MAV_PARAM_TYPE_REAL32 # Standard float type
    )


# --- SOFT ATTACK FUNCTION ---

offset = 0.0
def soft_attack(driftspeed: float, interval: float = 0.1, run_for: int | None = None, reset: bool = True, latitude_deg: float = -35):
    """
    Docstring for soft_attack
    
    :param driftspeed: Speed of drift in m/s
    :type driftspeed: float
    :param interval: Time interval between updates in seconds, defaults to 0.1, which is 10 updates per second
    :type interval: float
    :param run_for: Duration to run the attack in seconds, defaults to None which means run indefinitely
    :type run_for: int | None
    :param reset: Whether to reset the glitch parameter on exit, defaults to True
    :type reset: bool
    :param latitude_deg: Latitude in degrees for longitude conversion, defaults to -35 which is approx. ArduPilot SITL default
    :type latitude_deg: float
    :return: None
    """

    increment = driftspeed * interval  # meters per interval

    start_time = time.time()
    last_print_time = time.time()
    global offset
    try:
        while True:
            now = time.time()
            if run_for is not None and (now - start_time) > run_for:
                break
            offset += increment
            set_param(PARAM, meters_to_deg_lon(offset, latitude_deg))
            if now - last_print_time > 2.0:
                # only print every second
                print(f"Param update {1/interval:.0f} times in last 2 seconds.\nSet {PARAM} to {meters_to_deg_lon(offset, latitude_deg):.6f} degrees\t (which translates to: {offset:.2f} meters)")
                last_print_time = now
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n--- SOFT ATTACK STOPPED BY USER ---")
        print(f"Final Glitch Offset: {offset:.2f} meters")
        
        if reset:
            print("--- GLITCH PARAMETER RESET ---")
            set_param(PARAM, 0.0)

        raise

# --- STRESS TEST FUNCTION ---

def stress_test_soft_attack(min_v: float, max_v: float, steps: int = 10, duration_per_step: int = 15):
    """
    Performs a stress test of the soft_attack function by varying the drift speed
    from min_v to max_v in specified number of steps. Each drift speed is run for
    a fixed duration per step.
    
    :param min_v: Minimum drift speed in m/s
    :type min_v: float
    :param max_v: Maximum drift speed in m/s
    :type max_v: float
    :param steps: Number of steps between min_v and max_v, defaults to 10
    :type steps: int
    :param duration_per_step: Duration to run each drift speed in seconds, defaults to 15
    :type duration_per_step: int
    """

    try:
        for driftspeed in np.linspace(min_v, max_v, steps):
            print(f"\n--- STARTING SOFT ATTACK WITH DRIFT SPEED: {driftspeed:.2f} m/s ---")
            soft_attack(driftspeed=driftspeed, run_for=duration_per_step, reset=False)
    except KeyboardInterrupt:
        print("\n--- STRESS TEST STOPPED BY USER ---")
        print(f"Last driftspeed tested: {driftspeed:.2f} m/s")

if __name__ == "__main__":

    # --- SINGLE SOFT ATTACK ---
    # drift_speed = 2.5  # m/s
    # print(f"Starting soft attack with drift speed of {drift_speed} m/s. Press Ctrl+C to stop.")
    # soft_attack(driftspeed=drift_speed)

    # --- STRESS TEST ---
    min_drift_speed = 2.2  # m/s
    max_drift_speed = 2.5  # m/s
    steps = 5  # number of different drift speeds to test

    print(f"Starting stress test of soft attack with drift speeds from {min_drift_speed} m/s to {max_drift_speed} m/s in {steps} steps.")
    stress_test_soft_attack(min_drift_speed, max_drift_speed, steps)

