local del = Instance.new("HopperBin")
del.BinType = "Hammer"
del.Parent = game.Players.LocalPlayer.Backpack

local copy = Instance.new("HopperBin")
copy.BinType = "Clone"
copy.Parent = game.Players.LocalPlayer.Backpack

local grab = Instance.new("HopperBin")
grab.BinType = "GameTool"
grab.Parent = game.Players.LocalPlayer.Backpack

local work = game.Workspace

for i,v in pairs(work:GetDescendants()) do
    if v:IsA("BasePart") then
        v.Locked = false
    end
end