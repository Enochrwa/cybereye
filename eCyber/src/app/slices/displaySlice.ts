import { createSlice, PayloadAction } from "@reduxjs/toolkit";

// ✅ Define the interface for the state
interface IDisplay {
  isAuthModalOpen: boolean;
  isBackendUp: boolean;
}

// ✅ Define the initial state
const initialState: IDisplay = {
  isAuthModalOpen: false,
  isBackendUp:false,
};

// ✅ Create the slice
const displaySlice = createSlice({
  name: "display",
  initialState,
  reducers: {
    setAuthModalState: (state, action: PayloadAction<boolean>) => {
      state.isAuthModalOpen = action.payload;
    },
    setIsBackendUp :(state, action:PayloadAction<boolean>) =>{
      state.isBackendUp = action.payload
    }
  },
});

// ✅ Export actions and reducer
export const { setAuthModalState, setIsBackendUp } = displaySlice.actions;
export default displaySlice.reducer
